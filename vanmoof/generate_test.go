package vanmoof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// lastLine returns the last non-empty line, where printGeneratedCert prints the certificate
func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

// writeConfig marshals cfg to a temporary JSON file and returns its path
func writeConfig(t *testing.T, cfg genConfig) string {
	t.Helper()
	return writeConfigRaw(t, string(must(json.Marshal(cfg))))
}

// writeConfigRaw writes content to a temporary file and returns its path
func writeConfigRaw(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// with returns a copy of p changed by f, for a table of parameters each wrong in one way
func with(p CertificateParams, f func(*CertificateParams)) CertificateParams {
	f(&p)
	return p
}

// A generated certificate carries exactly the fields asked for, its signature verifies
// against the signing key, and generation is deterministic.
func TestGenerateCertificate(t *testing.T) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userID := make([]byte, 16)
	userID[6], userID[8] = 0x40, 0x80
	authPub := make([]byte, 32)
	authPub[0] = 7
	expires := time.Now().Add(7 * 24 * time.Hour)

	params := CertificateParams{ID: 123456, FrameModule: "BBBBBB00001AA", BikeModule: "AAAAA000001AA",
		Expires: expires, Role: 0x07, UserID: userID, PublicKey: authPub}
	cert, err := GenerateCertificate(params, signPriv)
	if err != nil {
		t.Fatal(err)
	}

	data, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		t.Fatalf("not base64: %v", err)
	}
	if !ed25519.Verify(signPub, data[64:], data[:64]) {
		t.Error("the signing key does not verify the certificate it signed")
	}

	res := CheckCertificate(cert, Expect{PublicKey: base64.StdEncoding.EncodeToString(authPub)})
	if res.ID != 123456 || res.FrameModule != "BBBBBB00001AA" || res.BikeModule != "AAAAA000001AA" ||
		res.Expires.Unix() != expires.Unix() || res.Role != 0x07 || !bytes.Equal(res.UserID, userID) || !bytes.Equal(res.PublicKey, authPub) {
		t.Errorf("certificate parsed back as %+v", res)
	}
	if !res.PublicKeyVerified {
		t.Error("not recognized as being for the authorized key")
	}

	// Canonical CBOR and Ed25519 both being deterministic, the same input gives the same output
	if again, _ := GenerateCertificate(params, signPriv); again != cert {
		t.Error("not deterministic")
	}
}

// A certificate signed by a key the bike trusts is valid, as it would be on a bike whose
// firmware trusts your own signing key.
func TestGenerateCertificateTrusted(t *testing.T) {
	ca := trustTestCA(t)
	userID := make([]byte, 16)
	userID[6], userID[8] = 0x40, 0x80
	pub := make([]byte, 32)
	params := CertificateParams{ID: 1, FrameModule: "BBBBBB00001AA", BikeModule: "BBBBBB00001AA",
		Expires: time.Now().Add(7 * 24 * time.Hour), Role: 0x07, UserID: userID, PublicKey: pub}
	cert, err := GenerateCertificate(params, ca)
	if err != nil {
		t.Fatal(err)
	}
	res := CheckCertificate(cert, Expect{PublicKey: base64.StdEncoding.EncodeToString(pub),
		Bike: &Bike{FrameNumber: "BBBBBB00001AA", BleProfile: "ELECTRIFIED_2022"}})
	if !res.Valid || !res.SignatureVerified {
		t.Errorf("a certificate signed by a trusted key is not valid: %v", res.Errors)
	}
}

// Each field has to be present, of the right size, and in range
func TestGenerateCertificateErrors(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userID := make([]byte, 16)
	userID[6], userID[8] = 0x40, 0x80
	pub := make([]byte, 32)
	good := CertificateParams{FrameModule: "BBBBBB00001AA", BikeModule: "BBBBBB00001AA",
		Expires: time.Now().Add(time.Hour), Role: 7, UserID: userID, PublicKey: pub}

	tests := []struct {
		name   string
		params CertificateParams
		key    ed25519.PrivateKey
	}{
		{"short signing key", good, key[:63]},
		{"empty AFM", with(good, func(p *CertificateParams) { p.FrameModule = "" }), key},
		{"empty ABM", with(good, func(p *CertificateParams) { p.BikeModule = "" }), key},
		{"invalid UTF-8 AFM", with(good, func(p *CertificateParams) { p.FrameModule = "\xff" }), key},
		{"invalid UTF-8 ABM", with(good, func(p *CertificateParams) { p.BikeModule = "\xff" }), key},
		{"short public key", with(good, func(p *CertificateParams) { p.PublicKey = pub[:31] }), key},
		{"short UUID", with(good, func(p *CertificateParams) { p.UserID = userID[:15] }), key},
		{"unset expiry", with(good, func(p *CertificateParams) { p.Expires = time.Time{} }), key},
		{"expiry after 2106", with(good, func(p *CertificateParams) { p.Expires = time.Unix(1<<32, 0) }), key},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := GenerateCertificate(tt.params, tt.key); err == nil {
				t.Error("no error")
			}
		})
	}

	// The parameters are otherwise well-formed, so each case above fails for its own reason
	if _, err := GenerateCertificate(good, key); err != nil {
		t.Errorf("good parameters rejected: %v", err)
	}
}

// A config becomes the right parameters, with the documented defaults, or an error naming the
// field at fault.
func TestParamsFromConfig(t *testing.T) {
	priv, pub, _ := GenerateED25519()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	cfg := genConfig{SigningKey: priv, PublicKey: pub, AFM: "BBBBBB00001AA", ABM: "AAAAA000001AA",
		Role: "Owner", UserUUID: leakUUID, Expires: "2030-06-01T00:00:00Z", ID: 42}
	params, key, err := paramsFromConfig(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if params.ID != 42 || params.FrameModule != "BBBBBB00001AA" || params.BikeModule != "AAAAA000001AA" ||
		params.Role != 0x07 || !params.Expires.Equal(time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)) || len(key) != ed25519.PrivateKeySize {
		t.Errorf("params %+v, key %d bytes", params, len(key))
	}
	if !bytes.Equal(params.PublicKey, mustDecode(pub)) {
		t.Error("public key not used")
	}

	// Defaults: the bike module is the frame module, the key the signing key's own, and
	// validity_days counts from now.
	cfg = genConfig{SigningKey: priv, AFM: "BBBBBB00001AA", Role: "7", UserUUID: leakUUID, ValidityDays: 10}
	params, key, err = paramsFromConfig(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if params.BikeModule != "BBBBBB00001AA" {
		t.Errorf("ABM didn't default to the AFM: %q", params.BikeModule)
	}
	if !params.Expires.Equal(now.Add(10 * 24 * time.Hour)) {
		t.Errorf("expiry %v, want 10 days from now", params.Expires)
	}
	if !bytes.Equal(params.PublicKey, key.Public().(ed25519.PublicKey)) {
		t.Error("public key didn't default to the signing key's own")
	}

	errs := []struct {
		name string
		cfg  genConfig
	}{
		{"signing_key", genConfig{SigningKey: "!!", AFM: "BBBBBB00001AA", Role: "7", UserUUID: leakUUID, ValidityDays: 1}},
		{"public_key", genConfig{SigningKey: priv, PublicKey: "AAAA", AFM: "BBBBBB00001AA", Role: "7", UserUUID: leakUUID, ValidityDays: 1}},
		{"user_uuid", genConfig{SigningKey: priv, AFM: "BBBBBB00001AA", Role: "7", UserUUID: "nope", ValidityDays: 1}},
		{"role", genConfig{SigningKey: priv, AFM: "BBBBBB00001AA", Role: "chief", UserUUID: leakUUID, ValidityDays: 1}},
		{"expiry", genConfig{SigningKey: priv, AFM: "BBBBBB00001AA", Role: "7", UserUUID: leakUUID}},
	}
	for _, tt := range errs {
		if _, _, err := paramsFromConfig(tt.cfg, now); err == nil {
			t.Errorf("%s: no error", tt.name)
		}
	}
}

// The remaining branches of the field parsers that TestParamsFromConfig doesn't reach
func TestParseHelpers(t *testing.T) {
	// A 32-byte seed expands into a full private key
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 1
	if k, err := parseSigningKey(base64.StdEncoding.EncodeToString(seed)); err != nil || len(k) != ed25519.PrivateKeySize {
		t.Errorf("seed: err %v, %d bytes", err, len(k))
	}
	// A 33-byte public key with a leading zero is accepted, the zero dropped
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if k, err := parseAuthorizedKey(base64.StdEncoding.EncodeToString(make([]byte, 33)), priv); err != nil || len(k) != 32 {
		t.Errorf("33-byte key: err %v, %d bytes", err, len(k))
	}
	// A public key that isn't base64
	if _, err := parseAuthorizedKey("!!", priv); err == nil {
		t.Error("accepted a public key that isn't base64")
	}
	// Valid hexadecimal, but not 16 bytes
	if _, err := parseUserUUID("1234"); err == nil {
		t.Error("accepted a 2-byte UUID")
	}
	// A hexadecimal role number
	if r, err := parseRole("0x42"); err != nil || r != 0x42 {
		t.Errorf("0x42: %d, %v", r, err)
	}
	// An unparseable expires
	if _, err := expiryFromConfig(genConfig{Expires: "yesterday"}, time.Now()); err == nil {
		t.Error("accepted an invalid expires")
	}
}

// GenerateCert reads a config and prints a certificate for it, applying the defaults, or an
// error for a config it can't use.
func TestGenerateCert(t *testing.T) {
	priv, pub, _ := GenerateED25519()
	valid := genConfig{SigningKey: priv, PublicKey: pub, AFM: "BBBBBB00001AA", Role: "Owner", UserUUID: leakUUID, ValidityDays: 30, ID: 4242}

	out := captureStdout(t, func() {
		if err := GenerateCert(writeConfig(t, valid), true); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Certificate:") || !strings.Contains(out, "Certificate ID:") {
		t.Fatalf("output:\n%s", out)
	}
	res := CheckCertificate(lastLine(out), Expect{PublicKey: pub})
	if res.ID != 4242 || res.FrameModule != "BBBBBB00001AA" || res.AccessLevel() != "Owner" || !res.PublicKeyVerified {
		t.Errorf("generated certificate parsed back as %+v", res)
	}

	// Defaults: a random ID (no debug line for it), the signing key's own public key, the AFM
	// as the ABM.
	noDefaults := genConfig{SigningKey: priv, AFM: "BBBBBB00001AA", Role: "Owner", UserUUID: leakUUID, ValidityDays: 30}
	out = captureStdout(t, func() {
		if err := GenerateCert(writeConfig(t, noDefaults), false); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "Certificate ID:") {
		t.Error("the certificate ID is only shown with -debug")
	}
	res = CheckCertificate(lastLine(out), Expect{})
	if res.ID == 0 || res.BikeModule != "BBBBBB00001AA" {
		t.Errorf("defaults not applied: %+v", res)
	}
	if !bytes.Equal(res.PublicKey, mustDecode(pub)) {
		t.Error("public key didn't default to the signing key's own")
	}

	errorCases := map[string]string{
		"missing file":    filepath.Join(t.TempDir(), "nope.json"),
		"invalid JSON":    writeConfigRaw(t, "{"),
		"unknown field":   writeConfigRaw(t, `{"nonsense":1}`),
		"bad signing key": writeConfigRaw(t, `{"signing_key":"!!","afm":"BBBBBB00001AA","role":"Owner","user_uuid":"`+leakUUID+`","validity_days":30}`),
		"empty AFM":       writeConfig(t, genConfig{SigningKey: priv, Role: "Owner", UserUUID: leakUUID, ValidityDays: 30}),
	}
	for name, path := range errorCases {
		if err := GenerateCert(path, false); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// -redact hides the certificate, the keys, the frame numbers and the UUID in the output
func TestGenerateCertRedacted(t *testing.T) {
	priv, pub, _ := GenerateED25519()
	cfg := genConfig{SigningKey: priv, PublicKey: pub, AFM: "LEAKYA12345ZZ", ABM: "LEAKYA12345ZZ",
		Role: "Owner", UserUUID: leakUUID, Expires: "2030-01-02T15:04:05Z", ID: 4242}

	// The exact certificate those fields produce, to make sure it never shows up redacted
	userID, _ := parseUserUUID(leakUUID)
	params := CertificateParams{ID: 4242, FrameModule: "LEAKYA12345ZZ", BikeModule: "LEAKYA12345ZZ",
		Expires: time.Date(2030, 1, 2, 15, 4, 5, 0, time.UTC), Role: 0x07, UserID: userID, PublicKey: mustDecode(pub)}
	cert, err := GenerateCertificate(params, ed25519.PrivateKey(mustDecode(priv)))
	if err != nil {
		t.Fatal(err)
	}

	defer SetRedaction(false, false)
	SetRedaction(true, false)
	out := captureStdout(t, func() {
		if err := GenerateCert(writeConfig(t, cfg), true); err != nil {
			t.Fatal(err)
		}
	})
	for _, secret := range []string{cert, pub, leakUUID, "LEAKYA12345ZZ"} {
		if strings.Contains(out, secret) {
			t.Errorf("-redact output leaks %q:\n%s", secret, out)
		}
	}
}

// Whatever a config contains, generateCert never panics and its output, and that of the error
// it reports, has nothing for a terminal to interpret.
func FuzzGenerateCert(f *testing.F) {
	priv, pub, _ := GenerateED25519()
	seed := func(cfg genConfig) []byte { return must(json.Marshal(cfg)) }
	f.Add(seed(genConfig{SigningKey: priv, PublicKey: pub, AFM: "BBBBBB00001AA", Role: "Owner", UserUUID: leakUUID, ValidityDays: 30}))
	f.Add(seed(genConfig{SigningKey: priv, AFM: "AAAAA000001AA", Role: "0x42", UserUUID: leakUUID, Expires: "2030-01-02T15:04:05Z", ID: 7}))
	f.Add([]byte("{"))
	f.Add([]byte(`{"afm":"\u202e\u001b[2J","role":"999","user_uuid":"zz"}`))
	f.Add([]byte(`{"signing_key":"AAAA","unknown":1}`))
	f.Fuzz(func(t *testing.T, config []byte) {
		defer SetRedaction(false, false)
		for _, redact := range []bool{false, true} {
			SetRedaction(redact, false)
			out := captureStdout(t, func() {
				if err := generateCert(config, true); err != nil {
					fmt.Printf("Error: %v\n", ScrubText(err.Error()))
				}
			})
			if unescaped(out) {
				t.Errorf("output not escaped: %q", out)
			}
		}
	})
}

// Whatever its fields, a certificate GenerateCertificate produces carries exactly them and a
// signature its signing key verifies; invalid fields are rejected, never encoded.
func FuzzGenerateRoundTrip(f *testing.F) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	user := make([]byte, 16)
	user[6], user[8] = 0x40, 0x80
	key := make([]byte, 32)
	key[0] = 9
	f.Add("BBBBBB00001AA", "BBBBBB00001AA", int64(time.Now().Add(time.Hour).Unix()), uint8(7), user, key, uint32(123456))
	f.Add("", "x", int64(0), uint8(0), user[:15], key[:31], uint32(0))
	f.Add("\u202e", "AAAAA000001AA", int64(-1), uint8(255), user, key, uint32(1)<<31)
	f.Add("BBBBBB00001AA", "BBBBBB00001AA", int64(math.MaxUint32), uint8(0x42), user, key, uint32(math.MaxUint32))
	f.Fuzz(func(t *testing.T, frame, bike string, expiry int64, role uint8, user, key []byte, id uint32) {
		params := CertificateParams{ID: id, FrameModule: frame, BikeModule: bike,
			Expires: time.Unix(expiry, 0), Role: role, UserID: user, PublicKey: key}
		cert, err := GenerateCertificate(params, signPriv)
		if err != nil {
			return // invalid parameters are rejected, not encoded into a certificate
		}
		data, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			t.Fatalf("not base64: %v", err)
		}
		if !ed25519.Verify(signPub, data[64:], data[:64]) {
			t.Error("the signing key does not verify the certificate it signed")
		}
		res := CheckCertificate(cert, Expect{})
		if res.ID != id || res.FrameModule != frame || res.BikeModule != bike || res.Expires.Unix() != expiry ||
			res.Role != role || !bytes.Equal(res.UserID, user) || !bytes.Equal(res.PublicKey, key) {
			t.Errorf("generated %+v, parsed back %+v", params, res)
		}
	})
}
