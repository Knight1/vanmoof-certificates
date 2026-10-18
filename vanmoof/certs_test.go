package vanmoof

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestIsS6Certificate(t *testing.T) {
	s6Bike := Bike{FrameNumber: "AAAAA000000AA", BleProfile: "ELECTRIFIED_2025"}
	sa5Bike := Bike{FrameNumber: "BBBBBB00000AA", BleProfile: "ELECTRIFIED_2022"}
	// Some SA5 frame numbers have the S6 shape (5 letters + 6 digits)
	sa5S6Shaped := Bike{FrameNumber: "AAAAA000001AA", BleProfile: "ELECTRIFIED_2022"}

	tests := []struct {
		name      string
		r         certResult
		requested *Bike
		want      bool
	}{
		{"matched S6 bike", certResult{matchedBike: &s6Bike}, nil, true},
		{"matched non-S6 bike, non-S6-shaped frame ID", certResult{matchedBike: &sa5Bike, frameID: []byte("BBBBBB00000AA")}, nil, false},
		{"matched SA5 bike, S6-shaped frame ID", certResult{matchedBike: &sa5S6Shaped, frameID: []byte("AAAAA000001AA")}, nil, false},
		{"requested S6 bike", certResult{frameID: []byte("AAAAA000000AA")}, &s6Bike, true},
		{"requested SA5 bike, S6-shaped frame ID", certResult{frameID: []byte("AAAAA000001AA")}, &sa5S6Shaped, false},
		{"-framenumber without a BLE profile, S6-shaped frame ID", certResult{frameID: []byte("AAAAA000000AA")}, &Bike{FrameNumber: "AAAAA000000AA"}, true},
		{"no matched bike, S6-shaped frame ID", certResult{frameID: []byte("AAAAA000000AA")}, nil, true},
		{"no matched bike, SA5-shaped frame ID", certResult{frameID: []byte("BBBBBB00000AA")}, nil, false},
		{"no matched bike, empty frame ID", certResult{}, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isS6Certificate(tt.r, tt.requested); got != tt.want {
				t.Errorf("isS6Certificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

// testCertFields returns the payload fields of a well-formed certificate for frame
func testCertFields(frame string) map[string]any {
	userID := make([]byte, 16)
	userID[6], userID[8] = 0x40, 0x80 // UUID v4 version and variant bits
	return map[string]any{
		"i": uint64(123456),
		"f": frame,
		"b": frame,
		"e": uint64(time.Now().Add(7 * 24 * time.Hour).Unix()),
		"r": uint64(0x07),
		"u": userID,
		"p": make([]byte, 32),
	}
}

// testCert encodes fields into a base64 certificate, signed with key, or with a random
// signature if key is nil
func testCert(t *testing.T, key ed25519.PrivateKey, fields map[string]any) string {
	t.Helper()
	payload, err := cbor.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return signedCert(t, key, payload)
}

// signedCert is a base64 certificate of payload, signed with key, or with a random
// signature if key is nil
func signedCert(t *testing.T, key ed25519.PrivateKey, payload []byte) string {
	t.Helper()
	signature := make([]byte, ed25519.SignatureSize)
	if key != nil {
		signature = ed25519.Sign(key, payload)
	} else {
		rand.Read(signature)
	}
	return base64.StdEncoding.EncodeToString(append(signature, payload...))
}

// trustTestCA adds a throwaway CA key to knownCAKeys for the duration of the test
func trustTestCA(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := knownCAKeys
	knownCAKeys = append(append([]string{}, old...), hex.EncodeToString(pub))
	t.Cleanup(func() { knownCAKeys = old })
	return priv
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Read while f runs, as more output than the pipe holds would block it
	out := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()
	stdout := os.Stdout
	os.Stdout = w
	f()
	os.Stdout = stdout
	w.Close()
	return <-out
}

// The default output may only say "Certificate valid" when every check that ran passed,
// and must show anything that couldn't be checked or looks suspicious.
func TestProcessCertificateVerdict(t *testing.T) {
	ca := trustTestCA(t)
	const sa5, s6, sa5S6Shaped = "BBBBBB00001AA", "AAAAA000001AA", "AAAAA000002AA"
	longLived := testCertFields(sa5)
	longLived["e"] = uint64(time.Now().AddDate(10, 0, 0).Unix())

	tests := []struct {
		name        string
		cert        string
		bike        *Bike    // the bike the certificate was requested for, or nil for -cert
		frameNumber string   // -framenumber
		verdict     string   // expected start of the output
		lines       []string // expected elsewhere in the output
	}{
		{"signed certificate", testCert(t, ca, testCertFields(sa5)), nil, "",
			"Certificate valid: " + sa5, nil},
		{"certificate for the requested bike", testCert(t, ca, testCertFields(sa5)), &Bike{BikeID: 42, FrameNumber: sa5, BleProfile: "ELECTRIFIED_2022"}, "",
			"Certificate valid: " + sa5, []string{"bike matched"}},
		{"certificate for another bike", testCert(t, ca, testCertFields(sa5)), &Bike{BikeID: 42, FrameNumber: "BBBBBB00002AA", BleProfile: "ELECTRIFIED_2022"}, "",
			"Certificate INVALID", []string{"✗ Bike ID 42 mismatch"}},
		{"certificate for a shared bike", testCert(t, ca, testCertFields(sa5)), &Bike{FrameNumber: sa5, BleProfile: "ELECTRIFIED_2022"}, "",
			"Certificate valid: " + sa5, []string{"bike matched"}},
		{"matching -framenumber", testCert(t, ca, testCertFields(sa5)), nil, sa5,
			"Certificate valid: " + sa5, nil},
		{"wrong -framenumber", testCert(t, ca, testCertFields(sa5)), nil, "BBBBBB00002AA",
			"Certificate INVALID", []string{"✗ Bike frame BBBBBB00002AA not found in certificate"}},
		{"warning on a valid certificate", testCert(t, ca, longLived), nil, "",
			"Certificate valid: " + sa5, []string{"⚠ Certificate expiry is suspiciously far in the future"}},
		{"S6 signature can't be verified", testCert(t, nil, testCertFields(s6)), &Bike{BikeID: 8, FrameNumber: s6, BleProfile: "ELECTRIFIED_2025"}, "",
			"Certificate valid, but signature not verified: " + s6, []string{"Note: " + s6SignatureNote}},
		{"S6-shaped frame offline, signature can't be verified", testCert(t, nil, testCertFields(s6)), nil, "",
			"Certificate valid, but signature not verified: " + s6, []string{"Note: " + s6SignatureNote}},
		{"SA5 with a bad signature", testCert(t, nil, testCertFields(sa5)), nil, "",
			"Certificate INVALID", []string{"✗ Signature INVALID"}},
		{"SA5 with an S6-shaped frame number and a bad signature", testCert(t, nil, testCertFields(sa5S6Shaped)), &Bike{BikeID: 7, FrameNumber: sa5S6Shaped, BleProfile: "ELECTRIFIED_2022"}, "",
			"Certificate INVALID", []string{"✗ Signature INVALID"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var valid bool
			out := captureStdout(t, func() {
				if tt.bike != nil {
					valid = checkCertificate(tt.cert, Expect{Bike: tt.bike, Bikes: []Bike{*tt.bike}}, false).Valid
				} else {
					valid = ProcessCertificate(tt.cert, "", tt.frameNumber, false)
				}
			})
			// What it reports (and so the exit status) has to match what it prints
			if want := !strings.HasPrefix(tt.verdict, "Certificate INVALID"); valid != want {
				t.Errorf("reported valid = %v, want %v", valid, want)
			}
			if !strings.HasPrefix(out, tt.verdict) {
				t.Errorf("output starts %q, want %q", strings.SplitN(out, "\n", 2)[0], tt.verdict)
			}
			for _, line := range tt.lines {
				if !strings.Contains(out, line) {
					t.Errorf("output lacks %q:\n%s", line, out)
				}
			}
			if !strings.Contains(strings.Join(tt.lines, "\n"), "⚠") && strings.Contains(out, "⚠") {
				t.Errorf("unexpected warning:\n%s", out)
			}
		})
	}
}

// Each role the bike knows (its MQTT users ble-role-<role>, see acl.txt) is reported by
// name without a warning, and any other one as unknown, with a warning
func TestCertificateRoles(t *testing.T) {
	ca := trustTestCA(t)
	roles := map[uint64]string{
		7:  "Owner",
		11: "Guest",
		17: "Bike Doctor",
		22: "Bike Hunter",
		55: "QA Engineer",
		66: "R&D Engineer",
		// Shown in hex
		0x00: "Unknown Role (0x00)",
		0x0F: "Unknown Role (0x0F)",
		0xFF: "Unknown Role (0xFF)",
	}
	for role, name := range roles {
		fields := testCertFields("BBBBBB00001AA")
		fields["r"] = role
		res := CheckCertificate(testCert(t, ca, fields), Expect{})
		wantWarnings := 0
		if strings.HasPrefix(name, "Unknown") {
			wantWarnings = 1
		}
		if !res.Valid || res.AccessLevel() != name || len(res.Warnings) != wantWarnings {
			t.Errorf("role %d: valid = %v, access level %q, warnings %q; want %q", role, res.Valid, res.AccessLevel(), res.Warnings, name)
		}
	}
}

// A number too big for its field makes the certificate invalid, instead of being cut off
// into one that looks valid
func TestCertificateFieldRanges(t *testing.T) {
	ca := trustTestCA(t)
	inAWeek := uint64(time.Now().Add(7 * 24 * time.Hour).Unix())
	tests := []struct {
		field string
		value uint64
		err   string // the only error, or "" if it's valid
	}{
		{"i", 1<<32 - 1, ""},
		{"i", 1<<32 + 123456, "Field 'i' is out of range (expected uint32, got 4295090752)"},
		{"e", 1<<32 + inAWeek, fmt.Sprintf("Field 'e' is out of range (expected uint32, got %d)", 1<<32+inAWeek)},
		{"r", 0xFF, ""}, // valid, but unknown
		{"r", 0x107, "Field 'r' is out of range (expected uint8, got 263)"},
	}
	for _, tt := range tests {
		fields := testCertFields("BBBBBB00001AA")
		fields[tt.field] = tt.value
		res := CheckCertificate(testCert(t, ca, fields), Expect{})
		if got := strings.Join(res.Errors, "; "); got != tt.err || res.Valid != (tt.err == "") {
			t.Errorf("%s = %d: errors %q, want %q", tt.field, tt.value, res.Errors, tt.err)
		}
	}

	// Neither shows up cut off: an expiry in 2162 as one in 2026, or role 0x107 as an owner
	fields := testCertFields("BBBBBB00001AA")
	fields["e"], fields["r"] = 1<<32+inAWeek, uint64(0x107)
	res := CheckCertificate(testCert(t, ca, fields), Expect{})
	if !res.Expires.IsZero() || res.AccessLevel() == "Owner" || len(res.Warnings) != 0 {
		t.Errorf("expires %v, access level %q, warnings %q", res.Expires, res.AccessLevel(), res.Warnings)
	}
	out := captureStdout(t, func() { ProcessCertificate(testCert(t, ca, fields), "", "", true) })
	if !strings.Contains(out, "✗ Field 'e' is out of range") || !strings.Contains(out, "✗ Field 'r' is out of range") ||
		strings.Contains(out, time.Unix(int64(inAWeek), 0).Format("2006-01-02")) || strings.Contains(out, "Access Level: Owner") {
		t.Errorf("debug output:\n%s", out)
	}

	// A missing number is reported as missing, not as zero
	fields = testCertFields("BBBBBB00001AA")
	delete(fields, "e")
	if res := CheckCertificate(testCert(t, ca, fields), Expect{}); strings.Join(res.Errors, "; ") != "Missing required field: 'e'" {
		t.Errorf("without an expiry: errors %q", res.Errors)
	}
}

// A field of the wrong type, an empty bike module or a zero expiry makes the certificate
// invalid. A field the bike doesn't know is ignored, even with a number for its name.
func TestCertificateFieldTypes(t *testing.T) {
	ca := trustTestCA(t)
	tests := []struct {
		field string
		value any
		err   string // one of the errors
	}{
		{"i", "123456", "Field 'i' has incorrect type (expected uint)"},
		{"f", uint64(1), "Field 'f' has incorrect type (expected string)"},
		{"b", uint64(1), "Field 'b' has incorrect type (expected string)"},
		{"u", "user", "Field 'u' has incorrect type (expected bytes)"},
		{"p", "key", "Field 'p' has incorrect type (expected bytes)"},
		{"b", "", "Bike ID (b) is empty"},
		{"e", uint64(0), "Expiry timestamp is zero"},
	}
	for _, tt := range tests {
		fields := testCertFields("BBBBBB00001AA")
		fields[tt.field] = tt.value
		if res := CheckCertificate(testCert(t, ca, fields), Expect{}); res.Valid || !slices.Contains(res.Errors, tt.err) {
			t.Errorf("%s = %#v: valid = %v, errors %q; want %q", tt.field, tt.value, res.Valid, res.Errors, tt.err)
		}
	}

	fields := map[any]any{uint64(8): "unknown"}
	for k, v := range testCertFields("BBBBBB00001AA") {
		fields[k] = v
	}
	payload, err := cbor.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if res := CheckCertificate(signedCert(t, ca, payload), Expect{}); !res.Valid {
		t.Errorf("with a field named 8: errors %q", res.Errors)
	}
}

// A certificate for another user is invalid. The expected user ID may be written with or
// without dashes, in either case.
func TestCertificateUserID(t *testing.T) {
	ca := trustTestCA(t)
	fields := testCertFields("BBBBBB00001AA")
	fields["u"], _ = hex.DecodeString(strings.ReplaceAll(leakUUID, "-", ""))
	cert := testCert(t, ca, fields)
	for userID, valid := range map[string]bool{
		leakUUID:                              true,
		strings.ToUpper(leakUUID):             true,
		strings.ReplaceAll(leakUUID, "-", ""): true,
		leakOwnerUUID:                         false,
	} {
		res := CheckCertificate(cert, Expect{UserID: userID})
		if res.Valid != valid || res.UserIDVerified != valid || valid != !strings.Contains(strings.Join(res.Errors, "\n"), "User ID mismatch") {
			t.Errorf("for %s: valid = %v, user ID verified = %v, errors %q", userID, res.Valid, res.UserIDVerified, res.Errors)
		}
	}
}

// A field that appears twice makes even a properly signed certificate invalid, as the bike
// might use another of its values than the one shown: here an owner's that's also R&D's
func TestCertificateDuplicateFields(t *testing.T) {
	ca := trustTestCA(t)
	payload, err := cbor.Marshal(testCertFields("BBBBBB00001AA"))
	if err != nil {
		t.Fatal(err)
	}
	if payload[0] != 0xa7 {
		t.Fatalf("payload starts with 0x%02x, want a map of 7 fields (0xa7)", payload[0])
	}
	key, _ := cbor.Marshal("r")
	value, _ := cbor.Marshal(uint64(0x42))
	payload = append(append(append([]byte{0xa8}, payload[1:]...), key...), value...)

	res := CheckCertificate(signedCert(t, ca, payload), Expect{})
	if res.Valid || !res.SignatureVerified || !strings.Contains(strings.Join(res.Errors, "\n"), `duplicate map key "r"`) {
		t.Errorf("valid = %v, signature verified = %v, errors %q", res.Valid, res.SignatureVerified, res.Errors)
	}
}

// The public key a certificate has to be for may have a 0x00 prefix (33 bytes); one that
// isn't base64, or too short, is an error
func TestVerifyPublicKey(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	b64 := base64.StdEncoding.EncodeToString
	tests := []struct {
		expected string
		verified bool
		err      string // start of the error, or "" for none
	}{
		{b64(key), true, ""},
		{b64(append([]byte{0}, key...)), true, ""},
		{b64(make([]byte, 32)), false, "Public key mismatch"},
		{"not base64!", false, "Error decoding expected public key"},
		{b64([]byte{1, 2, 3}), false, "Public key too short"},
	}
	for _, tt := range tests {
		r := certResult{publicKey: key}
		verifyPublicKey(&r, tt.expected)
		if r.pubKeyVerified != tt.verified || (tt.err == "") != (len(r.errors) == 0) || (tt.err != "" && !strings.HasPrefix(r.errors[0], tt.err)) {
			t.Errorf("%q: verified %v, errors %q", tt.expected, r.pubKeyVerified, r.errors)
		}
	}
}

// Debug output describes the certificate in full: which of the account's bikes it's for
// (or that it's for none), and how its signature was checked
func TestPrintVerbose(t *testing.T) {
	ca := trustTestCA(t)
	sa5 := Bike{BikeID: 42, Name: "Mine", FrameNumber: "BBBBBB00001AA", FrameSerial: "BBBBBB00001AA", BleProfile: "ELECTRIFIED_2022"}
	other := Bike{BikeID: 43, Name: "Other", FrameNumber: "BBBBBB00009AA", BleProfile: "ELECTRIFIED_2022"}
	pub := make([]byte, 32)
	pub[0] = 1
	fields := testCertFields(sa5.FrameNumber)
	fields["p"] = pub
	signed, unsigned := testCert(t, ca, fields), testCert(t, nil, fields)
	expect := Expect{PublicKey: base64.StdEncoding.EncodeToString(pub), Bike: &sa5, Bikes: []Bike{sa5, other}}
	shared := Bike{Name: "Shared", FrameNumber: "AAAAA000009AA"} // no bike ID

	// Without frame and bike module, and with a user ID too short for a UUID
	fields = testCertFields("")
	fields["u"] = make([]byte, 15)
	bare := testCert(t, ca, fields)
	// With a bike module that isn't a frame number
	fields = testCertFields(sa5.FrameNumber)
	fields["b"] = "ECU-1"
	module := testCert(t, ca, fields)

	tests := []struct {
		name   string
		cert   string
		expect Expect
		want   []string
	}{
		{"for one of the account's bikes", signed, expect, []string{
			"✓ Certificate matches one of your bikes", "Matched Bike ID: 42", "✓ Bike ID Verified: 42",
			"✓ Success: Public Key matches", "✓ Signature VALID with CA key"}},
		{"for none of them", signed, Expect{Bikes: []Bike{other}}, []string{
			"✗ Certificate does NOT match any of your bikes", "Your bikes: BBBBBB00009AA (ID: 43)"}},
		{"not signed by VanMoof", unsigned, expect, []string{"✗ Signature validation failed with all known CA keys"}},
		{"for another key", signed, Expect{PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}, []string{"✗ Warning: Key mismatch detected."}},
		{"for none of several bikes", signed, Expect{Bikes: []Bike{other, shared}}, []string{"Your bikes: BBBBBB00009AA (ID: 43), AAAAA000009AA\n"}},
		{"for another user", signed, Expect{UserID: leakUUID}, []string{
			"✗ User ID mismatch", "Expected: " + leakUUID, "Certificate: 00000000000040008000000000000000"}},
		{"for no bike", bare, Expect{}, []string{
			"AFM (Authorized Frame Module): \n", "ABM (Authorized Bike Module): \n", "User ID: " + strings.Repeat("00", 15) + " ✗ Invalid UUID"}},
		{"for another module", module, Expect{}, []string{"ABM (Authorized Bike Module): ECU-1 ✗ Invalid format"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := captureStdout(t, func() { checkCertificate(tt.cert, tt.expect, true) })
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
		})
	}
}

// A CA key that isn't one is skipped. Without any, a signature can't be checked: that
// doesn't make the certificate invalid, but it isn't reported as signed either.
func TestCAKeys(t *testing.T) {
	ca := trustTestCA(t)
	cert := testCert(t, ca, testCertFields("BBBBBB00001AA"))

	knownCAKeys = append([]string{"not a key"}, knownCAKeys...)
	var res CertificateResult
	out := captureStdout(t, func() { res = checkCertificate(cert, Expect{}, true) })
	if !res.Valid || !res.SignatureVerified || !strings.Contains(out, "✗ CA key 1: Invalid format") || !strings.Contains(out, "✓ Signature VALID with CA key 3") {
		t.Errorf("valid = %v, signature verified = %v:\n%s", res.Valid, res.SignatureVerified, out)
	}

	knownCAKeys = nil
	out = captureStdout(t, func() { res = checkCertificate(cert, Expect{}, true) })
	if !res.Valid || res.SignatureVerified || !strings.Contains(out, "No VanMoof CA public keys available") {
		t.Errorf("without CA keys: valid = %v, signature verified = %v:\n%s", res.Valid, res.SignatureVerified, out)
	}
}

// must returns the value of a call that worked, and panics with the error of one that failed
func TestMust(t *testing.T) {
	if v := must(42, nil); v != 42 {
		t.Errorf("must = %d, want 42", v)
	}
	failed := errors.New("failed")
	defer func() {
		if r := recover(); r != failed {
			t.Errorf("panic %v, want %v", r, failed)
		}
	}()
	must(0, failed)
}
