package vanmoof

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// realOneCRL is OneCRL as Firefox Remote Settings served it on 2026-10-27
// (testdata/onecrl/changeset.json.gz), and the chain it was signed with
// (testdata/onecrl/chain.pem), its signer's certificate valid from 2026-09-06 to 2026-11-25
func realOneCRL(t *testing.T) (body, chain []byte) {
	t.Helper()
	f, err := os.Open("testdata/onecrl/changeset.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if body, err = io.ReadAll(gz); err != nil {
		t.Fatal(err)
	}
	if chain, err = os.ReadFile("testdata/onecrl/chain.pem"); err != nil {
		t.Fatal(err)
	}
	return body, chain
}

// Mozilla's real OneCRL checks out with the embedded root, as Firefox checks it: the
// canonical JSON is what Mozilla signs. A record less, or the signer's certificate expired,
// and it doesn't.
func TestRealOneCRL(t *testing.T) {
	body, chain := realOneCRL(t)
	mozilla := certPool(contentSignatureRootPEM)
	signedOn := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	list, err := parseOneCRL(body)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(list.bySerial) + len(list.byKey); n < 1000 {
		t.Errorf("%d entries, want the 1907 records'", n)
	}
	if err := checkContentSignature(list.signed, list.signature, chain, mozilla, signedOn); err != nil {
		t.Errorf("Mozilla's own OneCRL: %v", err)
	}
	if err := checkContentSignature(list.signed, list.signature, chain, mozilla, time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)); err == nil ||
		!strings.Contains(err.Error(), "the signer's certificate") {
		t.Errorf("with the signer's certificate expired: err = %v", err)
	}
	if err := checkContentSignature(list.signed, list.signature, chain, testContentSigner.pool(), signedOn); err == nil {
		t.Error("checked out with another root")
	}
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	doc["changes"] = doc["changes"].([]any)[1:]
	shorter := must(parseOneCRL(must(json.Marshal(doc))))
	if err := checkContentSignature(shorter.signed, shorter.signature, chain, mozilla, signedOn); err == nil || err.Error() != "the signature doesn't match" {
		t.Errorf("a record less: err = %v", err)
	}
}

// pool is a pool of s's root
func (s *contentSigner) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(s.root)
	return pool
}

// A content signature checks out only with the mode Mozilla signs with, by a certificate
// for oneCRLSigner, for code signing, valid now, with a P-384 key, that chains up to one of
// the roots, over the very content
func TestCheckContentSignature(t *testing.T) {
	content := []byte(`{"data":[],"last_modified":"1"}`)
	now := time.Now()
	signed := contentSignature{X5U: contentChainURL, Mode: "p384ecdsa", Signature: testContentSigner.sign(content)}
	with := func(change func(*contentSignature)) contentSignature {
		sig := signed
		change(&sig)
		return sig
	}
	tests := []struct {
		name    string
		signer  *contentSigner // its chain, checked with its root, if not testContentSigner
		sig     contentSignature
		chain   string // if not the signer's
		content string // if not content
		at      time.Time
		err     string // the start of it, "" for none
	}{
		{"good", nil, signed, "", "", now, ""},
		{"padded", nil, with(func(s *contentSignature) { s.Signature += "==" }), "", "", now, ""},
		{"by another mode", nil, with(func(s *contentSignature) { s.Mode = "rs256" }), "", "", now, `unsupported signature mode "rs256"`},
		{"without a chain", nil, signed, "no PEM", "", now, "no certificate in " + contentChainURL},
		{"with an invalid certificate", nil, signed, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})), "", now,
			"invalid certificate in " + contentChainURL},
		{"chaining up to another root", nil, signed, string(forgedContentSigner.chain), "", now,
			"the signer's certificate: x509: certificate signed by unknown authority"},
		{"for another name", newContentSigner(p384Key(), func(c *x509.Certificate) { c.DNSNames = []string{"remote-settings.content-signature.mozilla.org"} }), signed, "", "", now,
			"the signer's certificate: x509: certificate is valid for remote-settings.content-signature.mozilla.org"},
		{"not for code signing", newContentSigner(p384Key(), func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }), signed, "", "", now,
			"the signer's certificate: x509: certificate specifies an incompatible key usage"},
		{"expired", nil, signed, "", "", now.Add(2 * time.Hour), "the signer's certificate: x509: certificate has expired"},
		{"with a P-256 key", newContentSigner(must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)), nil), signed, "", "", now, "the signer's key isn't ECDSA P-384"},
		{"with an RSA key", newContentSigner(must(rsa.GenerateKey(rand.Reader, 2048)), nil), signed, "", "", now, "the signer's key isn't ECDSA P-384"},
		{"not base64url", nil, with(func(s *contentSignature) { s.Signature = "!!" }), "", "", now, "invalid signature"},
		{"too short", nil, with(func(s *contentSignature) { s.Signature = s.Signature[:120] }), "", "", now, "invalid signature"},
		{"over other content", nil, signed, "", `{"data":[],"last_modified":"2"}`, now, "the signature doesn't match"},
		{"by another key", nil, with(func(s *contentSignature) { s.Signature = forgedContentSigner.sign(content) }), "", "", now, "the signature doesn't match"},
	}
	for _, tt := range tests {
		signer := cmp.Or(tt.signer, testContentSigner)
		chain, c := cmp.Or(tt.chain, string(signer.chain)), cmp.Or(tt.content, string(content))
		err := checkContentSignature([]byte(c), tt.sig, []byte(chain), signer.pool(), tt.at)
		if tt.err == "" && err != nil || tt.err != "" && (err == nil || !strings.HasPrefix(err.Error(), tt.err)) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.err)
		}
	}
}

// The canonical JSON has no whitespace, the keys sorted by code point, the numbers as they
// came, and everything but printable ASCII escaped
func TestCanonicalJSON(t *testing.T) {
	for in, want := range map[string]string{
		`{ "b": [1, 2.50, -0, 1e3], "a": {"z": null, "é": true, "B": false} }`: `{"a":{"B":false,"z":null,"\u00e9":true},"b":[1,2.50,-0,1e3]}`,
		`"quote \" backslash \\ slash / \b\f\n\r\t \u0001 \u007f"`:             `"quote \" backslash \\ slash / \b\f\n\r\t \u0001 \u007f"`,
		`"café 😀 \u2028"`: `"caf\u00e9 \ud83d\ude00 \u2028"`,
		`[]`:              `[]`,
		`{}`:              `{}`,
		`[[], {}, "", 0]`: `[[],{},"",0]`,
	} {
		var v any
		decoder := json.NewDecoder(strings.NewReader(in))
		decoder.UseNumber()
		if err := decoder.Decode(&v); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got := string(canonicalJSON(v)); got != want {
			t.Errorf("%s:\n got %s\nwant %s", in, got, want)
		}
	}
}

// The embedded root is Mozilla's content signing root, root-ca-production-amo, the one
// Firefox trusts, by its SHA-256 fingerprint
func TestContentSignatureRoot(t *testing.T) {
	block, rest := pem.Decode(contentSignatureRootPEM)
	if block == nil || len(bytes.TrimSpace(rest)) > 0 {
		t.Fatal("not one PEM block")
	}
	root := must(x509.ParseCertificate(block.Bytes))
	fingerprint := sha256.Sum256(root.Raw)
	if got := strings.ToUpper(hex.EncodeToString(fingerprint[:])); got != "C8A80E9AFAEF4E219B6FB5D7A71D0F101223BAC5001AC28F9B0D43DC59A106DB" || root.Subject.CommonName != "root-ca-production-amo" {
		t.Errorf("%s, SHA-256 %s", root.Subject, got)
	}
}
