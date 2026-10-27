package vanmoof

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Firefox Remote Settings signs each collection it serves, OneCRL included, with a content
// signature: ECDSA P-384 over the collection's canonical JSON, by a certificate for the
// collection that chains up to Mozilla's content signing root. The signature is checked as
// Firefox checks it, so a OneCRL that anyone between here and Mozilla changed, or served
// in its place, isn't taken for Mozilla's.

// oneCRLSigner is the name the certificate signing OneCRL is for
const oneCRLSigner = "onecrl.content-signature.mozilla.org"

// contentSignatureRootPEM is Mozilla's content signing root, root-ca-production-amo (as
// reissued in 2024, valid until 2200), the one Firefox trusts for content signatures: its
// security/manager/ssl/content-signature-prod.pem
//
//go:embed content-signature-prod.pem
var contentSignatureRootPEM []byte

// contentSignatureRoots are the roots a content signature's certificate has to chain up to.
// A var so a test can sign with a root of its own.
var contentSignatureRoots = certPool(contentSignatureRootPEM)

// certPool is a pool of the certificates in the PEM
func certPool(pemCerts []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemCerts)
	return pool
}

// contentSignature is the signature of a Remote Settings collection (its metadata's
// "signature")
type contentSignature struct {
	X5U       string `json:"x5u"`       // the URL of the signer's certificate chain, in PEM
	Mode      string `json:"mode"`      // "p384ecdsa"
	Signature string `json:"signature"` // base64url of r || s
}

// verifyContentSignature fetches the certificate chain sig names and checks that it signs
// content. The chain needs no protection of its own: it has to chain up to the root.
func (c *revocationChecker) verifyContentSignature(content []byte, sig contentSignature) error {
	chain, err := c.fetch(sig.X5U, nil)
	if err != nil {
		return err
	}
	return checkContentSignature(content, sig, chain, contentSignatureRoots, time.Now())
}

// checkContentSignature checks that sig signs content, with the first certificate of
// chainPEM: one for oneCRLSigner, for code signing, valid at now, that the rest of the
// chain links to one of roots
func checkContentSignature(content []byte, sig contentSignature, chainPEM []byte, roots *x509.CertPool, now time.Time) error {
	if sig.Mode != "p384ecdsa" {
		return fmt.Errorf("unsupported signature mode %q", sig.Mode)
	}
	var certs []*x509.Certificate
	for block, rest := pem.Decode(chainPEM); block != nil; block, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("invalid certificate in %s: %w", sig.X5U, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return fmt.Errorf("no certificate in %s", sig.X5U)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: oneCRLSigner, Intermediates: intermediates, Roots: roots,
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
		return fmt.Errorf("the signer's certificate: %w", err)
	}
	key, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() {
		return errors.New("the signer's key isn't ECDSA P-384")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(sig.Signature, "="))
	if err != nil || len(raw) != 96 {
		return errors.New("invalid signature")
	}
	hash := sha512.Sum384(append([]byte("Content-Signature:\x00"), content...))
	if !ecdsa.Verify(key, hash[:], new(big.Int).SetBytes(raw[:48]), new(big.Int).SetBytes(raw[48:])) {
		return errors.New("the signature doesn't match")
	}
	return nil
}

// canonicalJSON is v, as decoded with json.Decoder.UseNumber, in the canonical form Remote
// Settings signs: no whitespace, object keys sorted, everything but printable ASCII
// escaped (\uXXXX in lowercase hex, UTF-16 surrogate pairs beyond the BMP), numbers as
// they came.
func canonicalJSON(v any) []byte {
	var b bytes.Buffer
	writeCanonical(&b, v)
	return b.Bytes()
}

func writeCanonical(b *bytes.Buffer, v any) {
	switch v := v.(type) {
	case map[string]any:
		b.WriteByte('{')
		for i, key := range slices.Sorted(maps.Keys(v)) {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonicalString(b, key)
			b.WriteByte(':')
			writeCanonical(b, v[key])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, element := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, element)
		}
		b.WriteByte(']')
	case string:
		writeCanonicalString(b, v)
	case json.Number:
		b.WriteString(v.String())
	case bool:
		b.WriteString(strconv.FormatBool(v))
	default: // nil
		b.WriteString("null")
	}
}

func writeCanonicalString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r >= 0x20 && r < 0x7f {
				b.WriteRune(r)
				continue
			}
			for _, unit := range utf16.Encode([]rune{r}) {
				fmt.Fprintf(b, `\u%04x`, unit)
			}
		}
	}
	b.WriteByte('"')
}
