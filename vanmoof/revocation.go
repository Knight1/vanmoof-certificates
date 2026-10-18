package vanmoof

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Before a request goes out, the TLS certificate of the server it goes to, and each CA
// certificate it chains to (but the root), is checked for revocation: with OCSP (the
// response the server staples, or else the CA's responder) and with its CRL. A certificate
// that either check reports as revoked is refused, and so is one that neither confirms,
// unless SetAllowUnknownRevocation. Each certificate is checked once, and the connections
// are kept alive.

// ErrRevoked is wrapped by the error of a request to a server whose TLS certificate, or a CA
// certificate it chains to, OCSP or a CRL reports as revoked. The request isn't sent.
var ErrRevoked = errors.New("vanmoof: TLS certificate revoked")

// ErrRevocationUnknown is wrapped by the error of a request to a server for whose TLS
// certificate, or a CA certificate it chains to, neither OCSP nor a CRL confirms that it
// isn't revoked, e.g. as the CA's servers can't be reached. The request isn't sent, unless
// SetAllowUnknownRevocation allows it.
var ErrRevocationUnknown = errors.New("vanmoof: TLS certificate revocation unknown")

var allowUnknownRevocation atomic.Bool

// SetAllowUnknownRevocation sets whether a request goes out to a server for whose TLS
// certificate neither OCSP nor a CRL confirms that it isn't revoked (see
// ErrRevocationUnknown). One reported as revoked is refused either way.
func SetAllowUnknownRevocation(allow bool) {
	allowUnknownRevocation.Store(allow)
}

const (
	// revocationTimeout limits each fetch of an OCSP response or CRL
	revocationTimeout = 10 * time.Second
	// maxRevocationSize limits the size of an OCSP response or CRL
	maxRevocationSize = 32 << 20
	// clockSkew is how far the clocks of a CA and this computer may disagree
	clockSkew = 5 * time.Minute
)

var (
	checkedMu   sync.Mutex
	checkedBase http.RoundTripper // the transport checked is a copy of
	checked     *http.Transport
	checker     *revocationChecker
)

// checkedTransport returns the transport for requests over base, which is
// http.DefaultTransport: if it's an *http.Transport, a copy of it whose TLS connections
// check the server's certificates for revocation, the same one as long as base is, so its
// connections are kept alive and each certificate is checked once. Any other base, such as
// a test's, is used as it is, without a checker.
func checkedTransport(base http.RoundTripper) (http.RoundTripper, *revocationChecker) {
	t, ok := base.(*http.Transport)
	if !ok {
		return base, nil
	}
	checkedMu.Lock()
	defer checkedMu.Unlock()
	if base != checkedBase {
		checkedBase, checker, checked = base, newRevocationChecker(base), t.Clone()
		checked.TLSClientConfig = cmp.Or(checked.TLSClientConfig, new(tls.Config))
		checked.TLSClientConfig.VerifyConnection = checker.verifyConnection
		checked.TLSHandshakeTimeout += 2 * revocationTimeout // the check is part of the handshake
	}
	return checked, checker
}

// revocationStatus is what a check found out about a certificate
type revocationStatus int

const (
	statusUnknown revocationStatus = iota // nothing confirmed
	statusGood                            // not revoked
	statusRevoked
)

// checkResult is what OCSP or a CRL says about a certificate, with the details for messages
type checkResult struct {
	status revocationStatus
	detail string
}

// revocation is what the checks found out about a certificate
type revocation struct {
	once       sync.Once
	name       string
	ocsp, crl  checkResult
	shortLived bool        // see shortLived
	printed    atomic.Bool // whether debug output showed it
}

// status is revoked if either check reports it, and else good if either confirms it, or the
// certificate is short-lived
func (r *revocation) status() revocationStatus {
	switch {
	case r.ocsp.status == statusRevoked || r.crl.status == statusRevoked:
		return statusRevoked
	case r.ocsp.status == statusGood || r.crl.status == statusGood || r.shortLived:
		return statusGood
	}
	return statusUnknown
}

// shortLived reports whether cert is valid for 7 days at most, and names neither an OCSP
// responder nor a CRL: a CA may issue such a certificate without either, as it expires
// before a revocation would make a difference (CA/Browser Forum Baseline Requirements,
// 4.9.1.1). Whichever CA VanMoof's servers use next, that's no reason to refuse them.
func shortLived(cert *x509.Certificate) bool {
	return len(cert.OCSPServer) == 0 && len(cert.CRLDistributionPoints) == 0 && cert.NotAfter.Sub(cert.NotBefore) < 7*24*time.Hour
}

func (r *revocation) String() string {
	return fmt.Sprintf("%s (OCSP: %s; CRL: %s)", r.name, r.ocsp.detail, r.crl.detail)
}

// revocationChecker checks TLS certificates for revocation, each once, and fetches the OCSP
// responses and CRLs it needs with client, each CRL once
type revocationChecker struct {
	client *http.Client
	mu     sync.Mutex
	certs  map[[sha256.Size]byte]*revocation // by the certificate's SHA-256
	crls   map[string]*crlFetch              // by URL
}

// crlFetch is the CRL at a URL, fetched once
type crlFetch struct {
	once sync.Once
	crl  *x509.RevocationList
	err  error
}

func newRevocationChecker(transport http.RoundTripper) *revocationChecker {
	return &revocationChecker{
		client: &http.Client{Transport: transport, Timeout: revocationTimeout},
		certs:  make(map[[sha256.Size]byte]*revocation),
		crls:   make(map[string]*crlFetch),
	}
}

// verifyConnection is the TLS connections' VerifyConnection: it refuses a server whose
// certificate, or a CA certificate it chains to, is revoked, or not confirmed not to be,
// unless that's allowed
func (c *revocationChecker) verifyConnection(cs tls.ConnectionState) error {
	if len(cs.VerifiedChains) == 0 {
		// Only without certificate verification (InsecureSkipVerify): there's no issuer to
		// check the certificates with
		if allowUnknownRevocation.Load() {
			return nil
		}
		return fmt.Errorf("%w: %s (the certificate chain wasn't verified)", ErrRevocationUnknown, cs.ServerName)
	}
	for _, r := range c.check(cs.VerifiedChains[0], cs.OCSPResponse) {
		switch r.status() {
		case statusRevoked:
			return fmt.Errorf("%w: %s", ErrRevoked, r)
		case statusUnknown:
			if !allowUnknownRevocation.Load() {
				return fmt.Errorf("%w: %s; -allow-unknown-revocation connects anyway", ErrRevocationUnknown, r)
			}
		}
	}
	return nil
}

// check returns what the checks found out about each certificate of chain but its root,
// checking each the first time only; staple is the server's OCSP response for the first
func (c *revocationChecker) check(chain []*x509.Certificate, staple []byte) []*revocation {
	results := make([]*revocation, len(chain)-1)
	var wg sync.WaitGroup
	for i := range results {
		r := c.entry(chain[i])
		results[i] = r
		wg.Go(func() {
			r.once.Do(func() {
				var stapled []byte
				if i == 0 {
					stapled = staple // it's the server's own certificate's
				}
				var checks sync.WaitGroup
				checks.Go(func() { r.ocsp = c.checkOCSP(chain[i], chain[i+1], stapled) })
				checks.Go(func() { r.crl = c.checkCRL(chain[i], chain[i+1]) })
				checks.Wait()
				r.shortLived = shortLived(chain[i])
			})
		})
	}
	wg.Wait()
	return results
}

// entry returns what the checks found out, or will, about cert
func (c *revocationChecker) entry(cert *x509.Certificate) *revocation {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := sha256.Sum256(cert.Raw)
	r, ok := c.certs[key]
	if !ok {
		r = &revocation{name: cmp.Or(cert.Subject.CommonName, strings.Join(cert.DNSNames, ", "))}
		c.certs[key] = r
	}
	return r
}

// print prints, once for each, what the checks found out about the certificates of the
// connection (debug output)
func (c *revocationChecker) print(cs *tls.ConnectionState) {
	if len(cs.VerifiedChains) == 0 {
		return // not checked, as allowed
	}
	chain := cs.VerifiedChains[0]
	for _, cert := range chain[:len(chain)-1] {
		if r := c.entry(cert); !r.printed.Swap(true) {
			verdict := "not revoked"
			switch {
			case r.status() != statusGood:
				verdict = "not confirmed, connected anyway (-allow-unknown-revocation)"
			case r.shortLived:
				verdict = "short-lived, so there's no revocation to check"
			}
			fmt.Printf("[DEBUG] TLS certificate %s: %s\n", printable(r.String()), verdict)
		}
	}
}

// checkOCSP asks OCSP about cert, which issuer issued: the response the server stapled, if
// it's usable, and else the CA's responders
func (c *revocationChecker) checkOCSP(cert, issuer *x509.Certificate, staple []byte) checkResult {
	result := checkResult{detail: "no responder"}
	if len(staple) > 0 {
		if result = ocspResult(staple, cert, issuer); result.status != statusUnknown {
			result.detail += ", stapled"
			return result
		}
		result.detail = "stapled response: " + result.detail
	}
	request := must(ocsp.CreateRequest(cert, issuer, nil))
	for _, url := range cert.OCSPServer {
		response, err := c.fetch(url, request)
		if err != nil {
			result.detail = err.Error()
			continue
		}
		if result = ocspResult(response, cert, issuer); result.status != statusUnknown {
			return result
		}
	}
	return result
}

// ocspResult is what the OCSP response der says about cert: if issuer signed it, or a
// responder issuer authorized for OCSP, and it's current
func ocspResult(der []byte, cert, issuer *x509.Certificate) checkResult {
	resp, err := ocsp.ParseResponseForCert(der, cert, issuer)
	if err != nil {
		return checkResult{detail: "invalid response: " + err.Error()}
	}
	now := time.Now()
	// The parser checks that issuer signed the responder's certificate, but not that it's
	// for OCSP: any certificate of the CA's, such as another site's, could vouch for cert
	if resp.Certificate != nil && (!slices.Contains(resp.Certificate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) ||
		!current(resp.Certificate.NotBefore, resp.Certificate.NotAfter, now)) {
		return checkResult{detail: "the responder's certificate isn't one for OCSP"}
	}
	if !current(resp.ThisUpdate, resp.NextUpdate, now) {
		return checkResult{detail: "response not current"}
	}
	switch resp.Status {
	case ocsp.Good:
		return checkResult{statusGood, "good"}
	case ocsp.Revoked:
		return checkResult{statusRevoked, "revoked on " + resp.RevokedAt.Format(time.DateOnly)}
	}
	return checkResult{detail: "the responder doesn't know it"}
}

// current reports whether a response or CRL valid from thisUpdate to nextUpdate is valid
// now. One without nextUpdate never is: as the zero time, that's long past.
func current(thisUpdate, nextUpdate, now time.Time) bool {
	return !thisUpdate.After(now.Add(clockSkew)) && !now.After(nextUpdate.Add(clockSkew))
}

// checkCRL looks cert up in the CRLs it names (LDAP ones aside), which issuer signs
func (c *revocationChecker) checkCRL(cert, issuer *x509.Certificate) checkResult {
	result := checkResult{detail: "no CRL"}
	for _, url := range cert.CRLDistributionPoints {
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			continue
		}
		crl, err := c.crl(url)
		if err != nil {
			result.detail = err.Error()
			continue
		}
		if result = crlResult(crl, url, cert, issuer); result.status != statusUnknown {
			return result
		}
	}
	return result
}

// crl returns the CRL at url, fetching it the first time only
func (c *revocationChecker) crl(url string) (*x509.RevocationList, error) {
	c.mu.Lock()
	f, ok := c.crls[url]
	if !ok {
		f = new(crlFetch)
		c.crls[url] = f
	}
	c.mu.Unlock()
	f.once.Do(func() {
		var der []byte
		if der, f.err = c.fetch(url, nil); f.err == nil {
			if f.crl, f.err = x509.ParseRevocationList(der); f.err != nil {
				f.err = fmt.Errorf("invalid CRL from %s: %w", url, f.err)
			}
		}
	})
	return f.crl, f.err
}

// fetch returns the body of url's response: to a GET, or with an OCSP request, a POST
func (c *revocationChecker) fetch(url string, ocspRequest []byte) ([]byte, error) {
	var resp *http.Response
	var err error
	if ocspRequest == nil {
		resp, err = c.client.Get(url)
	} else {
		resp, err = c.client.Post(url, "application/ocsp-request", bytes.NewReader(ocspRequest))
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRevocationSize+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	if len(body) > maxRevocationSize {
		return nil, fmt.Errorf("%s: more than %d bytes", url, maxRevocationSize)
	}
	return body, nil
}

// crlResult is what crl, fetched from url, says about cert: if issuer signed it, it's
// current, and it covers cert
func crlResult(crl *x509.RevocationList, url string, cert, issuer *x509.Certificate) checkResult {
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return checkResult{detail: fmt.Sprintf("%s isn't signed by the issuer: %v", url, err)}
	}
	if !current(crl.ThisUpdate, crl.NextUpdate, time.Now()) {
		return checkResult{detail: url + " isn't current"}
	}
	if !crlCovers(crl, url, cert) {
		return checkResult{detail: url + " doesn't cover the certificate"}
	}
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return checkResult{statusRevoked, "revoked on " + e.RevocationTime.Format(time.DateOnly)}
		}
	}
	return checkResult{statusGood, "good"}
}

// oidIssuingDistributionPoint is the CRL extension that says which certificates the CRL
// covers: when the CA splits its revoked certificates over several CRLs, for example
var oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}

// issuingDistributionPoint is that extension (RFC 5280, 5.2.5)
type issuingDistributionPoint struct {
	DistributionPoint          asn1.RawValue  `asn1:"optional,tag:0"` // a DistributionPointName
	OnlyContainsUserCerts      bool           `asn1:"optional,tag:1"`
	OnlyContainsCACerts        bool           `asn1:"optional,tag:2"`
	OnlySomeReasons            asn1.BitString `asn1:"optional,tag:3"`
	IndirectCRL                bool           `asn1:"optional,tag:4"`
	OnlyContainsAttributeCerts bool           `asn1:"optional,tag:5"`
}

// crlCovers reports whether crl, fetched from url, covers cert: it has no critical extension
// this package doesn't know, and if it's for some of the issuer's certificates only, cert
// is one of them. Without that, the CRL of other certificates could vouch for cert.
func crlCovers(crl *x509.RevocationList, url string, cert *x509.Certificate) bool {
	for _, e := range crl.RevokedCertificateEntries {
		if slices.ContainsFunc(e.Extensions, func(ext pkix.Extension) bool { return ext.Critical }) {
			return false
		}
	}
	for _, ext := range crl.Extensions {
		switch {
		case ext.Id.Equal(oidIssuingDistributionPoint):
			if !idpCovers(ext.Value, url, cert) {
				return false
			}
		case ext.Critical:
			return false
		}
	}
	return true
}

// idpCovers reports whether a CRL with the issuingDistributionPoint der, fetched from url,
// covers cert: the extension names url (if it names any), and doesn't limit the CRL to
// certificates of another kind, some revocation reasons, or other issuers
func idpCovers(der []byte, url string, cert *x509.Certificate) bool {
	var idp issuingDistributionPoint
	if rest, err := asn1.Unmarshal(der, &idp); err != nil || len(rest) > 0 {
		return false
	}
	if idp.OnlySomeReasons.BitLength > 0 || idp.IndirectCRL || idp.OnlyContainsAttributeCerts ||
		idp.OnlyContainsUserCerts && cert.IsCA || idp.OnlyContainsCACerts && !cert.IsCA {
		return false
	}
	return len(idp.DistributionPoint.FullBytes) == 0 || slices.Contains(distributionPointURLs(idp.DistributionPoint.Bytes), url)
}

// distributionPointURLs returns the URLs of a DistributionPointName: those of its fullName
func distributionPointURLs(der []byte) []string {
	var fullName asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &fullName); err != nil || len(rest) > 0 || fullName.Class != asn1.ClassContextSpecific || fullName.Tag != 0 {
		return nil
	}
	var urls []string
	for names := fullName.Bytes; len(names) > 0; {
		var name asn1.RawValue
		var err error
		if names, err = asn1.Unmarshal(names, &name); err != nil {
			return nil
		}
		if name.Class == asn1.ClassContextSpecific && name.Tag == 6 { // uniformResourceIdentifier
			urls = append(urls, string(name.Bytes))
		}
	}
	return urls
}
