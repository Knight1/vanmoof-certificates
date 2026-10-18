package vanmoof

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestIsS6Certificate(t *testing.T) {
	s6Bike := BikeData{FrameNumber: "AAAAA000000AA", BleProfile: "ELECTRIFIED_2025"}
	sa5Bike := BikeData{FrameNumber: "BBBBBB00000AA", BleProfile: "ELECTRIFIED_2022"}
	// Some SA5 frame numbers have the S6 shape (5 letters + 6 digits)
	sa5S6Shaped := BikeData{FrameNumber: "AAAAA000001AA", BleProfile: "ELECTRIFIED_2022"}

	tests := []struct {
		name      string
		r         certResult
		requested *BikeData
		want      bool
	}{
		{"matched S6 bike", certResult{matchedBike: &s6Bike}, nil, true},
		{"matched non-S6 bike, non-S6-shaped frame ID", certResult{matchedBike: &sa5Bike, frameID: []byte("BBBBBB00000AA")}, nil, false},
		{"matched SA5 bike, S6-shaped frame ID", certResult{matchedBike: &sa5S6Shaped, frameID: []byte("AAAAA000001AA")}, nil, false},
		{"requested S6 bike", certResult{frameID: []byte("AAAAA000000AA")}, &s6Bike, true},
		{"requested SA5 bike, S6-shaped frame ID", certResult{frameID: []byte("AAAAA000001AA")}, &sa5S6Shaped, false},
		{"-framenumber without a BLE profile, S6-shaped frame ID", certResult{frameID: []byte("AAAAA000000AA")}, &BikeData{FrameNumber: "AAAAA000000AA"}, true},
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
func testCertFields(frame string) map[string]interface{} {
	userID := make([]byte, 16)
	userID[6], userID[8] = 0x40, 0x80 // UUID v4 version and variant bits
	return map[string]interface{}{
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
func testCert(t *testing.T, key ed25519.PrivateKey, fields map[string]interface{}) string {
	t.Helper()
	payload, err := cbor.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, ed25519.SignatureSize)
	if key != nil {
		signature = ed25519.Sign(key, payload)
	} else if _, err := rand.Read(signature); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(append(signature, payload...))
}

// trustTestCA adds a throwaway CA key to knownCAKeys for the duration of the test
func trustTestCA(t *testing.T) ed25519.PrivateKey {
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
	stdout := os.Stdout
	os.Stdout = w
	f()
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
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
		bike        *BikeData // the bike the certificate was requested for, or nil for -cert
		frameNumber string    // -framenumber
		verdict     string    // expected start of the output
		lines       []string  // expected elsewhere in the output
	}{
		{"signed certificate", testCert(t, ca, testCertFields(sa5)), nil, "",
			"Certificate valid: " + sa5, nil},
		{"certificate for the requested bike", testCert(t, ca, testCertFields(sa5)), &BikeData{BikeID: 42, FrameNumber: sa5, BleProfile: "ELECTRIFIED_2022"}, "",
			"Certificate valid: " + sa5, []string{"bike matched"}},
		{"certificate for another bike", testCert(t, ca, testCertFields(sa5)), &BikeData{BikeID: 42, FrameNumber: "BBBBBB00002AA", BleProfile: "ELECTRIFIED_2022"}, "",
			"Certificate INVALID", []string{"✗ Bike ID 42 mismatch"}},
		{"certificate for a shared bike", testCert(t, ca, testCertFields(sa5)), &BikeData{FrameNumber: sa5, BleProfile: "ELECTRIFIED_2022"}, "",
			"Certificate valid: " + sa5, []string{"bike matched"}},
		{"matching -framenumber", testCert(t, ca, testCertFields(sa5)), nil, sa5,
			"Certificate valid: " + sa5, nil},
		{"wrong -framenumber", testCert(t, ca, testCertFields(sa5)), nil, "BBBBBB00002AA",
			"Certificate INVALID", []string{"✗ Bike frame BBBBBB00002AA not found in certificate"}},
		{"warning on a valid certificate", testCert(t, ca, longLived), nil, "",
			"Certificate valid: " + sa5, []string{"⚠ Certificate expiry is suspiciously far in the future"}},
		{"S6 signature can't be verified", testCert(t, nil, testCertFields(s6)), &BikeData{BikeID: 8, FrameNumber: s6, BleProfile: "ELECTRIFIED_2025"}, "",
			"Certificate valid, but signature not verified: " + s6, []string{"Note: " + s6SignatureNote}},
		{"S6-shaped frame offline, signature can't be verified", testCert(t, nil, testCertFields(s6)), nil, "",
			"Certificate valid, but signature not verified: " + s6, []string{"Note: " + s6SignatureNote}},
		{"SA5 with a bad signature", testCert(t, nil, testCertFields(sa5)), nil, "",
			"Certificate INVALID", []string{"✗ Signature INVALID"}},
		{"SA5 with an S6-shaped frame number and a bad signature", testCert(t, nil, testCertFields(sa5S6Shaped)), &BikeData{BikeID: 7, FrameNumber: sa5S6Shaped, BleProfile: "ELECTRIFIED_2022"}, "",
			"Certificate INVALID", []string{"✗ Signature INVALID"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				if tt.bike != nil {
					checkCertificate(tt.cert, "", tt.bike, "", []BikeData{*tt.bike}, false)
				} else {
					ProcessCertificate(tt.cert, "", tt.frameNumber, false)
				}
			})
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
