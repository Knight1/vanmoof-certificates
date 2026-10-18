package vanmoof

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// hosts are VanMoof's servers
var hosts = []string{must(url.Parse(apiBaseURL)).Host, must(url.Parse(bikeApiBaseURL)).Host, must(url.Parse(vehicleRegistryBaseURL)).Host}

// pkiCert is a certificate of a test PKI, with its key
type pkiCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var pkiSerial atomic.Int64

// issue issues a certificate from template, signed by issuer, or else self-signed. Without
// NotAfter, it's valid for the hour before and after now.
func issue(t testing.TB, issuer *pkiCert, template *x509.Certificate) pkiCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template.SerialNumber = big.NewInt(pkiSerial.Add(1))
	if template.NotAfter.IsZero() {
		template.NotBefore, template.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	}
	parent, signer := template, key
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pkiCert{cert, key}
}

// newCA issues a CA certificate, whose own revocation OCSP and the CRL at the URLs tell
func newCA(t testing.TB, issuer *pkiCert, name string, ocspURLs, crlURLs []string) pkiCert {
	return issue(t, issuer, &x509.Certificate{Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, OCSPServer: ocspURLs, CRLDistributionPoints: crlURLs})
}

// newLeaf issues a server certificate for host
func newLeaf(t testing.TB, issuer *pkiCert, host string, ocspURLs, crlURLs []string) pkiCert {
	return issue(t, issuer, &x509.Certificate{Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, OCSPServer: ocspURLs, CRLDistributionPoints: crlURLs})
}

// ocspAnswer is issuer's OCSP response from template, signed by issuer, or by responder
// along with its certificate. Without ThisUpdate, it's valid from a minute ago for an hour.
func ocspAnswer(issuer pkiCert, responder *pkiCert, template ocsp.Response) []byte {
	signer := issuer
	if responder != nil {
		signer, template.Certificate = *responder, responder.cert
	}
	if template.ThisUpdate.IsZero() {
		template.ThisUpdate, template.NextUpdate = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	}
	return must(ocsp.CreateResponse(issuer.cert, signer.cert, template, signer.key))
}

// crlOf is a CRL from template, signed by issuer. Without ThisUpdate, it's valid from a
// minute ago for an hour.
func crlOf(issuer pkiCert, template x509.RevocationList) []byte {
	template.Number = big.NewInt(1)
	if template.ThisUpdate.IsZero() {
		template.ThisUpdate, template.NextUpdate = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	}
	return must(x509.CreateRevocationList(rand.Reader, &template, issuer.cert, issuer.key))
}

// revocationServers is a test PKI, a root CA and an intermediate one, with VanMoof's
// servers: one TLS server for all their hosts, with a certificate from the intermediate CA
// for each, and the CAs' OCSP responders and CRLs on another server. Until the test says
// otherwise, nothing is revoked. http.DefaultTransport reaches both servers, and only them.
type revocationServers struct {
	root, intermediate pkiCert
	leaves             map[string]pkiCert // by host
	api, ca            *httptest.Server

	mu                      sync.Mutex     // for the test to change what the servers do
	ocspRevoked, crlRevoked []*big.Int     // the serial numbers OCSP and the CRLs report revoked
	ocspDown, crlDown       bool           // they answer HTTP 500
	staple                  func() []byte  // what the TLS server staples, if anything
	fetches                 map[string]int // requests to the CA, by path

	connections, requests atomic.Int32 // to VanMoof's servers
}

func newRevocationServers(t *testing.T) *revocationServers {
	t.Helper()
	s := &revocationServers{leaves: make(map[string]pkiCert), fetches: make(map[string]int)}
	s.ca = httptest.NewServer(http.HandlerFunc(s.serveCA))
	t.Cleanup(s.ca.Close)
	s.root = newCA(t, nil, "Test Root CA", nil, nil)
	s.intermediate = newCA(t, &s.root, "Test Intermediate CA", []string{s.ca.URL + "/ocsp/root"}, []string{s.ca.URL + "/crl/root.crl"})
	for _, host := range hosts {
		s.leaves[host] = newLeaf(t, &s.intermediate, host, []string{s.ca.URL + "/ocsp/intermediate"}, []string{s.ca.URL + "/crl/intermediate.crl"})
	}

	s.api = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		io.WriteString(w, `{}`)
	}))
	s.api.Config.ErrorLog = log.New(io.Discard, "", 0) // the handshakes the checks refuse
	s.api.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			s.connections.Add(1)
		}
	}
	s.api.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		leaf := s.leaves[hello.ServerName]
		cert := &tls.Certificate{Certificate: [][]byte{leaf.cert.Raw, s.intermediate.cert.Raw}, PrivateKey: leaf.key}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.staple != nil {
			cert.OCSPStaple = s.staple()
		}
		return cert, nil
	}}
	s.api.StartTLS()
	t.Cleanup(s.api.Close)

	roots := x509.NewCertPool()
	roots.AddCert(s.root.cert)
	reachOnly(t, &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: s.dial})
	return s
}

// dial connects to the servers: VanMoof's hosts to the TLS server, the CA to its own
func (s *revocationServers) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(addr)
	switch {
	case slices.Contains(hosts, host):
		addr = s.api.Listener.Addr().String()
	case addr != s.ca.Listener.Addr().String():
		return nil, fmt.Errorf("the test tried to reach %s", addr)
	}
	return new(net.Dialer).DialContext(ctx, network, addr)
}

// reachOnly makes transport http.DefaultTransport for the rest of the test
func reachOnly(t *testing.T, transport *http.Transport) {
	old := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = old })
}

// serveCA answers the OCSP requests to /ocsp/<CA>, and serves the CA's CRL at
// /crl/<CA>.crl, for the root CA or the intermediate one
func (s *revocationServers) serveCA(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetches[r.URL.Path]++
	issuer := s.intermediate
	if strings.HasSuffix(r.URL.Path, "/root") || strings.HasSuffix(r.URL.Path, "/root.crl") {
		issuer = s.root
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/ocsp/") && !s.ocspDown:
		body, _ := io.ReadAll(r.Body)
		req, err := ocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		answer := ocsp.Response{Status: ocsp.Good, SerialNumber: req.SerialNumber}
		if containsSerial(s.ocspRevoked, req.SerialNumber) {
			answer.Status, answer.RevokedAt = ocsp.Revoked, time.Now().Add(-time.Hour)
		}
		w.Write(ocspAnswer(issuer, nil, answer))
	case strings.HasPrefix(r.URL.Path, "/crl/") && !s.crlDown:
		var revoked []x509.RevocationListEntry
		for _, serial := range s.crlRevoked {
			revoked = append(revoked, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: time.Now().Add(-time.Hour)})
		}
		w.Write(crlOf(issuer, x509.RevocationList{RevokedCertificateEntries: revoked}))
	default:
		http.Error(w, "down", http.StatusInternalServerError)
	}
}

func containsSerial(serials []*big.Int, serial *big.Int) bool {
	return slices.ContainsFunc(serials, func(s *big.Int) bool { return s.Cmp(serial) == 0 })
}

// change changes what the servers do
func (s *revocationServers) change(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

// fetched returns the requests to the CA so far, by path
func (s *revocationServers) fetched() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.fetches)
}

// get requests host's root, as the requests to VanMoof go out, and returns the output
func get(t *testing.T, host string, debug bool) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() { _, err = doHTTPRequest("GET", "https://"+host+"/", nil, nil, debug) })
	return out, err
}

// allowUnknown calls SetAllowUnknownRevocation for the rest of the test
func allowUnknown(t *testing.T, allow bool) {
	SetAllowUnknownRevocation(allow)
	t.Cleanup(func() { SetAllowUnknownRevocation(false) })
}

// Each certificate of the servers' chains is checked once, with OCSP and its CRL, and each
// CRL fetched once: the intermediate CA's for all three servers. Each server's connection
// is kept alive. Debug output tells what the checks found, once for each certificate.
func TestRevocationChecked(t *testing.T) {
	s := newRevocationServers(t)
	var out strings.Builder
	for _, host := range []string{hosts[0], hosts[1], hosts[0], hosts[2], hosts[1]} {
		o, err := get(t, host, true)
		if err != nil {
			t.Fatalf("%s: %v\n%s", host, err, o)
		}
		out.WriteString(o)
	}
	want := map[string]int{"/ocsp/intermediate": 3, "/crl/intermediate.crl": 1, "/ocsp/root": 1, "/crl/root.crl": 1}
	if got := s.fetched(); !maps.Equal(got, want) {
		t.Errorf("fetched %v, want %v", got, want)
	}
	if n := s.connections.Load(); n != 3 {
		t.Errorf("%d connections, want one for each server", n)
	}
	for _, name := range append(slices.Clone(hosts), "Test Intermediate CA") {
		line := "[DEBUG] TLS certificate " + name + " (OCSP: good; CRL: good): not revoked\n"
		if n := strings.Count(out.String(), line); n != 1 {
			t.Errorf("%q %d times in the output:\n%s", line, n, out.String())
		}
	}
}

// A certificate that OCSP or its CRL reports revoked is refused, whatever the other says,
// and even with SetAllowUnknownRevocation: the request isn't sent
func TestRevokedCertificates(t *testing.T) {
	tests := []struct {
		name   string
		revoke func(s *revocationServers)
	}{
		{"the server's, by OCSP", func(s *revocationServers) { s.ocspRevoked = []*big.Int{s.leaves[hosts[0]].cert.SerialNumber} }},
		{"the server's, by its CRL", func(s *revocationServers) { s.crlRevoked = []*big.Int{s.leaves[hosts[0]].cert.SerialNumber} }},
		{"the server's, by the OCSP response it staples", func(s *revocationServers) {
			s.staple = func() []byte {
				return ocspAnswer(s.intermediate, nil, ocsp.Response{Status: ocsp.Revoked, SerialNumber: s.leaves[hosts[0]].cert.SerialNumber, RevokedAt: time.Now()})
			}
		}},
		{"the CA's, by OCSP", func(s *revocationServers) { s.ocspRevoked = []*big.Int{s.intermediate.cert.SerialNumber} }},
		{"the CA's, by its CRL", func(s *revocationServers) { s.crlRevoked = []*big.Int{s.intermediate.cert.SerialNumber} }},
	}
	for _, tt := range tests {
		for _, allow := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, allowing unknown ones %v", tt.name, allow), func(t *testing.T) {
				s := newRevocationServers(t)
				s.change(func() { tt.revoke(s) })
				allowUnknown(t, allow)
				out, err := get(t, hosts[0], false)
				if !errors.Is(err, ErrRevoked) || s.requests.Load() != 0 || out != "" {
					t.Errorf("err = %v, %d requests, output %q", err, s.requests.Load(), out)
				}
			})
		}
	}
}

// A certificate that neither OCSP nor its CRL confirms is refused, unless that's allowed.
// Either confirming it is enough.
func TestRevocationUnknown(t *testing.T) {
	tests := []struct {
		ocspDown, crlDown, allow bool
		err                      error
	}{
		{true, true, false, ErrRevocationUnknown},
		{true, true, true, nil},
		{true, false, false, nil},
		{false, true, false, nil},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("OCSP down %v, CRL down %v, allowed %v", tt.ocspDown, tt.crlDown, tt.allow), func(t *testing.T) {
			s := newRevocationServers(t)
			s.change(func() { s.ocspDown, s.crlDown = tt.ocspDown, tt.crlDown })
			allowUnknown(t, tt.allow)
			out, err := get(t, hosts[0], true)
			if !errors.Is(err, tt.err) || (err == nil) != (s.requests.Load() == 1) {
				t.Fatalf("err = %v, %d requests\n%s", err, s.requests.Load(), out)
			}
			if err != nil && !strings.HasSuffix(err.Error(), "; -allow-unknown-revocation connects anyway") {
				t.Errorf("err = %v", err)
			}
			if tt.allow && !strings.Contains(out, "HTTP 500): not confirmed, connected anyway (-allow-unknown-revocation)") {
				t.Errorf("output:\n%s", out)
			}
		})
	}
}

// The OCSP response a server staples spares asking the responder, unless it's unusable:
// here signed with a certificate the CA issued, but not for OCSP
func TestStapledResponses(t *testing.T) {
	for name, usage := range map[string]x509.ExtKeyUsage{"from an OCSP responder": x509.ExtKeyUsageOCSPSigning, "from a server": x509.ExtKeyUsageServerAuth} {
		t.Run(name, func(t *testing.T) {
			s := newRevocationServers(t)
			responder := issue(t, &s.intermediate, &x509.Certificate{Subject: pkix.Name{CommonName: "Responder"}, ExtKeyUsage: []x509.ExtKeyUsage{usage}})
			s.change(func() {
				s.staple = func() []byte {
					return ocspAnswer(s.intermediate, &responder, ocsp.Response{Status: ocsp.Good, SerialNumber: s.leaves[hosts[0]].cert.SerialNumber})
				}
			})
			out, err := get(t, hosts[0], true)
			stapled := usage == x509.ExtKeyUsageOCSPSigning
			if asked := s.fetched()["/ocsp/intermediate"]; err != nil || (asked == 0) != stapled || strings.Contains(out, "OCSP: good, stapled;") != stapled {
				t.Errorf("err = %v, asked the responder %d times\n%s", err, asked, out)
			}
		})
	}
}

// Without certificate verification (InsecureSkipVerify), there's nothing to check the
// certificates with: the server is refused, unless that's allowed
func TestUnverifiedChain(t *testing.T) {
	s := newRevocationServers(t)
	reachOnly(t, &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DialContext: s.dial})
	if _, err := get(t, hosts[0], false); !errors.Is(err, ErrRevocationUnknown) || !strings.Contains(err.Error(), "wasn't verified") {
		t.Errorf("err = %v", err)
	}
	allowUnknown(t, true)
	if out, err := get(t, hosts[0], true); err != nil || strings.Contains(out, "TLS certificate") || s.requests.Load() != 1 {
		t.Errorf("err = %v, %d requests\n%s", err, s.requests.Load(), out)
	}
}

// A certificate valid for 7 days at most that names neither an OCSP responder nor a CRL, as
// a CA may issue it, has nothing to check, so it's no reason to refuse the server. One
// that's valid for longer, or names a CRL, is checked as any other.
func TestShortLivedCertificates(t *testing.T) {
	ca := newCA(t, nil, "Test CA", nil, nil)
	anHourAgo := time.Now().Add(-time.Hour)
	leaf := func(validity time.Duration, ocspURLs, crlURLs []string) *x509.Certificate {
		return issue(t, &ca, &x509.Certificate{Subject: pkix.Name{CommonName: "server"}, NotBefore: anHourAgo, NotAfter: anHourAgo.Add(validity),
			OCSPServer: ocspURLs, CRLDistributionPoints: crlURLs}).cert
	}
	checker := newRevocationChecker(roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") }))
	tests := []struct {
		name    string
		cert    *x509.Certificate
		err     error
		verdict string
	}{
		{"for 6 days", leaf(6*24*time.Hour, nil, nil), nil, "server (OCSP: no responder; CRL: no CRL): short-lived, so there's no revocation to check"},
		{"for 7 days", leaf(7*24*time.Hour, nil, nil), ErrRevocationUnknown, ""},
		{"for 6 days, with an OCSP responder", leaf(6*24*time.Hour, []string{"http://ca.example/ocsp"}, nil), ErrRevocationUnknown, ""},
		{"for 6 days, with a CRL", leaf(6*24*time.Hour, nil, []string{"http://ca.example/1.crl"}), ErrRevocationUnknown, ""},
	}
	for _, tt := range tests {
		cs := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{tt.cert, ca.cert}}}
		err := checker.verifyConnection(cs)
		if out := captureStdout(t, func() { checker.print(&cs) }); !errors.Is(err, tt.err) || !strings.Contains(out, tt.verdict) {
			t.Errorf("%s: err = %v\n%s", tt.name, err, out)
		}
	}
}

// The checks are added to a copy of an *http.Transport, the same one for the same
// transport, so its connections are kept alive. Any other one, such as a test's fake
// VanMoof, is used as it is.
func TestCheckedTransport(t *testing.T) {
	if got, checker := checkedTransport(roundTripFunc(nil)); checker != nil || got == nil {
		t.Errorf("a fake transport: %v, %v", got, checker)
	}
	base := &http.Transport{TLSHandshakeTimeout: time.Second}
	first, checker := checkedTransport(base)
	second, _ := checkedTransport(base)
	copied := first.(*http.Transport)
	if first != second || checker == nil || copied == base || copied.TLSClientConfig.VerifyConnection == nil ||
		base.TLSClientConfig != nil && base.TLSClientConfig.VerifyConnection != nil || copied.TLSHandshakeTimeout != time.Second+2*revocationTimeout {
		t.Errorf("checkedTransport = %+v, %v; second time %v", first, checker, second)
	}
}

// An OCSP response counts if the CA signed it, or a responder the CA authorized for OCSP,
// it's about the certificate, and it's current
func TestOCSPResult(t *testing.T) {
	ca := newCA(t, nil, "Test CA", nil, nil)
	cert, other := newLeaf(t, &ca, "server", nil, nil), newLeaf(t, &ca, "other", nil, nil)
	responder := func(usage x509.ExtKeyUsage, notAfter time.Time) *pkiCert {
		r := issue(t, &ca, &x509.Certificate{Subject: pkix.Name{CommonName: "Responder"}, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			NotBefore: notAfter.Add(-2 * time.Hour), NotAfter: notAfter})
		return &r
	}
	inAnHour, anHourAgo := time.Now().Add(time.Hour), time.Now().Add(-time.Hour)
	good := ocsp.Response{Status: ocsp.Good, SerialNumber: cert.cert.SerialNumber}
	with := func(edit func(r *ocsp.Response)) ocsp.Response {
		r := good
		edit(&r)
		return r
	}

	tests := []struct {
		name   string
		der    []byte
		status revocationStatus
		detail string // the start of it
	}{
		{"good", ocspAnswer(ca, nil, good), statusGood, "good"},
		{"revoked", ocspAnswer(ca, nil, with(func(r *ocsp.Response) {
			r.Status, r.RevokedAt = ocsp.Revoked, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		})), statusRevoked, "revoked on 2026-01-02"},
		{"unknown to the responder", ocspAnswer(ca, nil, with(func(r *ocsp.Response) { r.Status = ocsp.Unknown })), statusUnknown, "the responder doesn't know it"},
		{"from an OCSP responder", ocspAnswer(ca, responder(x509.ExtKeyUsageOCSPSigning, inAnHour), good), statusGood, "good"},
		{"from another certificate of the CA's", ocspAnswer(ca, responder(x509.ExtKeyUsageServerAuth, inAnHour), good), statusUnknown, "the responder's certificate isn't one for OCSP"},
		{"from an expired OCSP responder", ocspAnswer(ca, responder(x509.ExtKeyUsageOCSPSigning, anHourAgo), good), statusUnknown, "the responder's certificate isn't one for OCSP"},
		{"from another CA", ocspAnswer(newCA(t, nil, "Another CA", nil, nil), nil, good), statusUnknown, "invalid response: bad OCSP signature"},
		{"for another certificate", ocspAnswer(ca, nil, with(func(r *ocsp.Response) { r.SerialNumber = other.cert.SerialNumber })), statusUnknown, "invalid response: no response matching"},
		{"expired", ocspAnswer(ca, nil, with(func(r *ocsp.Response) { r.ThisUpdate, r.NextUpdate = anHourAgo.Add(-time.Hour), anHourAgo })), statusUnknown, "response not current"},
		{"from the future", ocspAnswer(ca, nil, with(func(r *ocsp.Response) { r.ThisUpdate, r.NextUpdate = inAnHour, inAnHour.Add(time.Hour) })), statusUnknown, "response not current"},
		{"valid forever", ocspAnswer(ca, nil, with(func(r *ocsp.Response) { r.ThisUpdate = anHourAgo })), statusUnknown, "response not current"},
		{"not a response", []byte("garbage"), statusUnknown, "invalid response"},
	}
	for _, tt := range tests {
		if r := ocspResult(tt.der, cert.cert, ca.cert); r.status != tt.status || !strings.HasPrefix(r.detail, tt.detail) {
			t.Errorf("%s: %+v, want %v %q", tt.name, r, tt.status, tt.detail)
		}
	}
}

// OCSP is asked with the stapled response, if it's usable, and else each responder in turn
// until one answers
func TestCheckOCSP(t *testing.T) {
	ca := newCA(t, nil, "Test CA", nil, nil)
	checker := newRevocationChecker(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Host {
		case "good.example":
			req := must(ocsp.ParseRequest(must(io.ReadAll(r.Body))))
			return httpResponse(r, http.StatusOK, string(ocspAnswer(ca, nil, ocsp.Response{Status: ocsp.Good, SerialNumber: req.SerialNumber}))), nil
		case "garbage.example":
			return httpResponse(r, http.StatusOK, "garbage"), nil
		}
		return httpResponse(r, http.StatusInternalServerError, ""), nil
	}))
	tests := []struct {
		name       string
		responders []string
		staple     []byte
		status     revocationStatus
		detail     string // the start of it
	}{
		{"no responder", nil, nil, statusUnknown, "no responder"},
		{"an unusable stapled response, no responder", nil, []byte("garbage"), statusUnknown, "stapled response: invalid response"},
		{"an unusable stapled response, a responder", []string{"http://good.example/"}, []byte("garbage"), statusGood, "good"},
		{"a responder down, then another", []string{"http://down.example/", "http://good.example/"}, nil, statusGood, "good"},
		{"a responder down", []string{"http://down.example/"}, nil, statusUnknown, "http://down.example/: HTTP 500"},
		{"a responder answering nonsense", []string{"http://garbage.example/"}, nil, statusUnknown, "invalid response"},
	}
	for _, tt := range tests {
		cert := newLeaf(t, &ca, "server", tt.responders, nil)
		if r := checker.checkOCSP(cert.cert, ca.cert, tt.staple); r.status != tt.status || !strings.HasPrefix(r.detail, tt.detail) {
			t.Errorf("%s: %+v, want %v %q", tt.name, r, tt.status, tt.detail)
		}
	}
}

// idpExtension is an issuingDistributionPoint CRL extension with distributionPoint (if not
// nil) and the fields after it, each DER
func idpExtension(distributionPoint []byte, fields ...[]byte) pkix.Extension {
	if distributionPoint != nil {
		fields = append([][]byte{must(asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: distributionPoint}))}, fields...)
	}
	value := must(asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: slices.Concat(fields...)}))
	return pkix.Extension{Id: oidIssuingDistributionPoint, Critical: true, Value: value}
}

// fullName is the DistributionPointName with the names, each DER
func fullName(names ...[]byte) []byte {
	return must(asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: slices.Concat(names...)}))
}

// uri is a GeneralName that's a URL
func uri(u string) []byte {
	return must(asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(u)}))
}

// The fields of an issuingDistributionPoint after its distributionPoint
var (
	onlyContainsUserCerts      = []byte{0x81, 0x01, 0xff}
	onlyContainsCACerts        = []byte{0x82, 0x01, 0xff}
	onlySomeReasons            = []byte{0x83, 0x02, 0x06, 0x40} // keyCompromise
	indirectCRL                = []byte{0x84, 0x01, 0xff}
	onlyContainsAttributeCerts = []byte{0x85, 0x01, 0xff}
)

// A CRL counts if the CA signed it, it's current, and it covers the certificate: it has no
// critical extension this package doesn't know, and if it's for some of the CA's
// certificates only, the certificate is one of them
func TestCRLResult(t *testing.T) {
	const crlURL = "http://ca.example/1.crl"
	root := newCA(t, nil, "Test Root CA", nil, nil)
	ca := newCA(t, &root, "Test CA", nil, nil)
	cert := newLeaf(t, &ca, "server", nil, nil)
	anHourAgo := time.Now().Add(-time.Hour)
	unknownOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	extensions := func(extensions ...pkix.Extension) x509.RevocationList {
		return x509.RevocationList{ExtraExtensions: extensions}
	}

	tests := []struct {
		name   string
		issuer pkiCert // signs the CRL: ca, unless set
		crl    x509.RevocationList
		of     *pkiCert // the certificate looked up: cert, unless set
		status revocationStatus
		detail string // the start of it
	}{
		{"good", pkiCert{}, x509.RevocationList{}, nil, statusGood, "good"},
		{"revoked", pkiCert{}, x509.RevocationList{RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(1), RevocationTime: anHourAgo}, {SerialNumber: cert.cert.SerialNumber, RevocationTime: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
		}}, nil, statusRevoked, "revoked on 2026-01-02"},
		{"from another CA", root, x509.RevocationList{}, nil, statusUnknown, crlURL + " isn't signed by the issuer"},
		{"expired", pkiCert{}, x509.RevocationList{ThisUpdate: anHourAgo.Add(-time.Hour), NextUpdate: anHourAgo}, nil, statusUnknown, crlURL + " isn't current"},
		{"for this URL", pkiCert{}, extensions(idpExtension(fullName(uri(crlURL)))), nil, statusGood, "good"},
		{"for this URL among others", pkiCert{}, extensions(idpExtension(fullName(uri("http://ca.example/0.crl"),
			must(asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("ca.example")})), uri(crlURL)))), nil, statusGood, "good"},
		{"for another URL, as part of the CA's CRL", pkiCert{}, extensions(idpExtension(fullName(uri("http://ca.example/2.crl")))), nil, statusUnknown, crlURL + " doesn't cover"},
		{"for a name relative to the CA", pkiCert{}, extensions(idpExtension(must(asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true})))), nil, statusUnknown, crlURL + " doesn't cover"},
		{"for a URL that isn't one", pkiCert{}, extensions(idpExtension(fullName([]byte{0x86, 0x05, 'x'}))), nil, statusUnknown, crlURL + " doesn't cover"},
		{"for a malformed distribution point", pkiCert{}, extensions(idpExtension([]byte{0xa0})), nil, statusUnknown, crlURL + " doesn't cover"},
		{"with a malformed issuingDistributionPoint", pkiCert{}, extensions(pkix.Extension{Id: oidIssuingDistributionPoint, Critical: true, Value: []byte{0x30}}), nil, statusUnknown, crlURL + " doesn't cover"},
		{"for servers' certificates", pkiCert{}, extensions(idpExtension(nil, onlyContainsUserCerts)), nil, statusGood, "good"},
		{"for servers' certificates, of a CA", pkiCert{}, extensions(idpExtension(nil, onlyContainsUserCerts)), &ca, statusUnknown, crlURL + " doesn't cover"},
		{"for CAs' certificates", pkiCert{}, extensions(idpExtension(nil, onlyContainsCACerts)), nil, statusUnknown, crlURL + " doesn't cover"},
		{"for CAs' certificates, of a CA", pkiCert{}, extensions(idpExtension(nil, onlyContainsCACerts)), &ca, statusGood, "good"},
		{"for some reasons", pkiCert{}, extensions(idpExtension(nil, onlySomeReasons)), nil, statusUnknown, crlURL + " doesn't cover"},
		{"for other CAs' certificates too", pkiCert{}, extensions(idpExtension(nil, indirectCRL)), nil, statusUnknown, crlURL + " doesn't cover"},
		{"for attribute certificates", pkiCert{}, extensions(idpExtension(nil, onlyContainsAttributeCerts)), nil, statusUnknown, crlURL + " doesn't cover"},
		{"with an unknown critical extension", pkiCert{}, extensions(pkix.Extension{Id: unknownOID, Critical: true, Value: []byte{0x05, 0x00}}), nil, statusUnknown, crlURL + " doesn't cover"},
		{"with an unknown extension", pkiCert{}, extensions(pkix.Extension{Id: unknownOID, Value: []byte{0x05, 0x00}}), nil, statusGood, "good"},
		{"with an entry's unknown critical extension", pkiCert{}, x509.RevocationList{RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(1), RevocationTime: anHourAgo, ExtraExtensions: []pkix.Extension{{Id: unknownOID, Critical: true, Value: []byte{0x05, 0x00}}}},
		}}, nil, statusUnknown, crlURL + " doesn't cover"},
	}
	for _, tt := range tests {
		issuer, of := cmp.Or(tt.issuer, ca), cmp.Or(tt.of, &cert)
		crl, err := x509.ParseRevocationList(crlOf(issuer, tt.crl))
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if r := crlResult(crl, crlURL, of.cert, ca.cert); r.status != tt.status || !strings.HasPrefix(r.detail, tt.detail) {
			t.Errorf("%s: %+v, want %v %q", tt.name, r, tt.status, tt.detail)
		}
	}
}

// The CRLs are looked up in turn until one counts, each fetched once
func TestCheckCRL(t *testing.T) {
	ca := newCA(t, nil, "Test CA", nil, nil)
	var mu sync.Mutex
	fetched := make(map[string]int)
	checker := newRevocationChecker(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		fetched[r.URL.String()]++
		mu.Unlock()
		switch r.URL.Host {
		case "good.example":
			return httpResponse(r, http.StatusOK, string(crlOf(ca, x509.RevocationList{}))), nil
		case "expired.example":
			return httpResponse(r, http.StatusOK, string(crlOf(ca, x509.RevocationList{ThisUpdate: time.Now().Add(-2 * time.Hour), NextUpdate: time.Now().Add(-time.Hour)}))), nil
		case "garbage.example":
			return httpResponse(r, http.StatusOK, "garbage"), nil
		}
		return httpResponse(r, http.StatusNotFound, ""), nil
	}))
	tests := []struct {
		name   string
		crls   []string
		status revocationStatus
		detail string // the start of it
	}{
		{"no CRL", nil, statusUnknown, "no CRL"},
		{"in LDAP only", []string{"ldap://ldap.example/cn=Test%20CA?certificateRevocationList"}, statusUnknown, "no CRL"},
		{"missing", []string{"http://missing.example/ca.crl"}, statusUnknown, "http://missing.example/ca.crl: HTTP 404"},
		{"not a CRL", []string{"http://garbage.example/ca.crl"}, statusUnknown, "invalid CRL from http://garbage.example/ca.crl"},
		{"expired, then one", []string{"http://expired.example/ca.crl", "https://good.example/ca.crl"}, statusGood, "good"},
		{"missing, then one", []string{"http://missing.example/ca.crl", "https://good.example/ca.crl"}, statusGood, "good"},
	}
	for _, tt := range tests {
		cert := newLeaf(t, &ca, "server", nil, tt.crls)
		if r := checker.checkCRL(cert.cert, ca.cert); r.status != tt.status || !strings.HasPrefix(r.detail, tt.detail) {
			t.Errorf("%s: %+v, want %v %q", tt.name, r, tt.status, tt.detail)
		}
	}
	if n := fetched["https://good.example/ca.crl"]; n != 1 {
		t.Errorf("a CRL fetched %d times, want once", n)
	}
}

// zeros reads as many zero bytes as asked for
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// A response too big, unreadable or not there is an error
func TestRevocationFetch(t *testing.T) {
	checker := newRevocationChecker(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Host {
		case "big.example":
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(zeros{}), Request: r}, nil
		case "broken.example":
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(broken{}), Request: r}, nil
		}
		return nil, errors.New("offline")
	}))
	for url, want := range map[string]string{
		"http://big.example/ca.crl":     fmt.Sprintf("http://big.example/ca.crl: more than %d bytes", maxRevocationSize),
		"http://broken.example/ca.crl":  "http://broken.example/ca.crl: broken",
		"http://offline.example/ca.crl": "offline",
	} {
		if _, err := checker.fetch(url, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", url, err, want)
		}
	}
}
