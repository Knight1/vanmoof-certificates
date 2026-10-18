package vanmoof

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

// Fuzz tests: their seeds run with every go test. To fuzz one for longer:
//
//	go test -run='^$' -fuzz=FuzzCheckCertificate -fuzztime=1m ./vanmoof

// unescaped reports whether output has invalid UTF-8, or a control character (other than
// a line break) or bidi override, which printable should have escaped
func unescaped(output string) bool {
	return !utf8.ValidString(output) || strings.ContainsFunc(output, func(r rune) bool {
		return r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r))
	})
}

// checkSelection fails if selected has an element twice, or one that isn't in from
func checkSelection[T comparable](t *testing.T, from, selected []T) {
	t.Helper()
	for i, s := range selected {
		if !slices.Contains(from, s) || slices.Index(selected, s) != i {
			t.Errorf("selected %v from %v", selected, from)
			return
		}
	}
}

// Any certificate, with any expected public key and frame number, is checked without a
// panic. A valid one has no errors, and control characters in it can't take over the
// printed result.
func FuzzCheckCertificate(f *testing.F) {
	pub, _, _ := ed25519.GenerateKey(nil)
	userID := make([]byte, 16)
	userID[6], userID[8] = 0x40, 0x80
	valid, _ := cbor.Marshal(map[string]any{"i": uint64(1), "f": "AAAAA000001AA", "b": "AAAAA000001AA",
		"e": uint64(time.Now().Add(time.Hour).Unix()), "r": uint64(7), "u": userID, "p": []byte(pub)})
	broken, _ := cbor.Marshal(map[string]any{"f": "AAA\x1b[2J\u202e", "b": 7, "e": -1, "r": uint64(1 << 40), "u": "x", "p": []byte{1}})
	signature := make([]byte, ed25519.SignatureSize)
	f.Add(append(signature, valid...), base64.StdEncoding.EncodeToString(pub), "AAAAA000001AA")
	f.Add(append(signature, valid[:len(valid)/2]...), "", "")
	f.Add(append(signature, broken...), "AAAA", "LEAKY\x1b[2J")
	f.Add(append(signature, 0xa1, 0x61, 0x66), "not base64!", "")
	f.Add([]byte{}, "", "")

	f.Fuzz(func(t *testing.T, data []byte, publicKey, frame string) {
		cert := base64.StdEncoding.EncodeToString(data)
		expect := Expect{PublicKey: publicKey}
		if frame != "" {
			expect.Bike = &Bike{FrameNumber: frame}
		}
		if res := CheckCertificate(cert, expect); res.Valid && len(res.Errors) > 0 {
			t.Errorf("valid, with errors: %q", res.Errors)
		}
		for _, debug := range []bool{false, true} {
			if out := captureStdout(t, func() { checkCertificate(cert, expect, debug) }); unescaped(out) {
				t.Errorf("output not escaped: %q", out)
			}
		}
	})
}

// Redaction never panics, and in every mode its output has nothing for a terminal to
// interpret, not even a line break
func FuzzRedaction(f *testing.F) {
	for _, s := range []string{"", "plain", "\x1b[2J", "\u202ereversed", "\xff\xfe", "a\nb",
		`{"token":"eyJhbGciOiJIUzI1NiJ9.e30.c2ln"}`, `{"a":[1,{"key":{"x":"y"}}],"name":"\u001b"}`,
		"LEAKY12345ZZ leak.user@example.com C0:FF:EE:00:00:01", `{"email":`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		defer SetRedaction(false, false)
		for _, mode := range [][2]bool{{false, false}, {true, false}, {false, true}} {
			SetRedaction(mode[0], mode[1])
			outputs := map[string]string{"printable": printable(s), "ScrubText": ScrubText(s), "Redact": Redact(s),
				"RedactID": RedactID(s), "redactJSON": redactJSON(s), "debugSecret": debugSecret(s)}
			for name, out := range outputs {
				if unescaped(out) || strings.Contains(out, "\n") {
					t.Errorf("%s(%q) with redaction %v = %q", name, s, mode, out)
				}
			}
		}
		if p := printable(s); printable(p) != p {
			t.Errorf("printable(%q) = %q, and printable of that %q", s, p, printable(p))
		}
	})
}

// jsonStrings returns the strings in a decoded JSON value
func jsonStrings(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		var s []string
		for _, e := range v {
			s = append(s, jsonStrings(e)...)
		}
		return s
	case map[string]any:
		var s []string
		for _, e := range v {
			s = append(s, jsonStrings(e)...)
		}
		return s
	}
	return nil
}

// A secret in a JSON document, such as a token, BLE key or bike message, is hidden by
// default and with -redact, wherever it is
func FuzzRedactJSONSecrets(f *testing.F) {
	for _, s := range []string{"eyJhbGciOiJIUzI1NiJ9.e30.c2ln", "1eaf1eaf1eaf1eaf", " ", "\u202e", "[REDACTED]x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, secret string) {
		doc, err := json.Marshal(map[string]any{
			"token":        secret,
			"refreshToken": secret,
			"data":         map[string]any{"bikeDetails": []any{map[string]any{"key": map[string]any{"encryptionKey": secret, "passcode": secret}}}},
			"messages":     []any{map[string]any{"content": secret}},
		})
		if err != nil {
			t.Skip()
		}
		var original struct{ Token string }
		json.Unmarshal(doc, &original) // the secret as JSON has it, e.g. invalid UTF-8 replaced
		if original.Token == "" || original.Token == redacted {
			t.Skip()
		}

		defer SetRedaction(false, false)
		for _, mode := range [][2]bool{{false, false}, {true, false}} {
			SetRedaction(mode[0], mode[1])
			var v any
			if err := json.Unmarshal([]byte(redactJSON(string(doc))), &v); err != nil {
				t.Fatalf("redacted JSON is broken: %v", err)
			}
			if slices.Contains(jsonStrings(v), original.Token) {
				t.Errorf("secret %q shown, with redaction %v", original.Token, mode)
			}
		}
	})
}

// User input is checked without a panic, and consistently
func FuzzInputValidation(f *testing.F) {
	for _, s := range []string{"", "0", "007", "2147483647", "2147483648", "-1", "+1", "1e3", "BBBBBB00001AA", "AAAAA000001AA",
		"ASY0000000", "bbbbbb00001aa", "user@example.com", "User <user@example.com>", " user@example.com",
		"Yd2bYMB3+vs4cCnDtPbcaM164KIl2zs05AK2jt/K6Gs=", "AA==", leakAuthToken, "a.b.c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, isID := ParseBikeID(s)
		if isID && (id < 0 || s == "" || strings.ContainsFunc(s, func(r rune) bool { return r < '0' || r > '9' })) {
			t.Errorf("ParseBikeID(%q) = %d, true", s, id)
		}
		if isID && LooksLikeFrameNumber(s) {
			t.Errorf("%q is both a bike ID and a frame number", s)
		}
		if ValidateFrameNumber(s) && !LooksLikeFrameNumber(s) {
			t.Errorf("%q is a valid frame number, but doesn't look like one", s)
		}
		if IsValidEd25519PublicKey(s) && !IsValidBase64(s) {
			t.Errorf("%q is a public key, but not base64", s)
		}
		if IsValidEmail(s) && strings.TrimSpace(s) != s {
			t.Errorf("%q is an email address with spaces around it", s)
		}
		isJWTExpired(s)
	})
}

// Any -bikes filter, or answer to the question which, selects each bike at most once, and
// only bikes of the list
func FuzzSelectBikes(f *testing.F) {
	bikes := []Bike{{BikeID: 1, FrameNumber: "BBBBBB00001AA"}, {BikeID: 2, FrameNumber: "AAAAA000002AA"}, {FrameNumber: "LKY0000003"}}
	for _, s := range [][2]string{{"all", ""}, {"1", ""}, {"1,2,1", ""}, {"BBBBBB00001AA, 2", ""}, {"ask", "1,3\n"},
		{"ask", "all\n"}, {"ask", "3,BBBBBB00001AA,1"}, {"ask", ""}, {",", ""}, {"99999999999999999999", ""}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, filter, answer string) {
		setStdin(t, answer)
		var selected []Bike
		captureStdout(t, func() { selected, _ = selectBikes(bikes, filter) })
		checkSelection(t, bikes, selected)
	})
}

// The same for invitations
func FuzzSelectInvitations(f *testing.F) {
	invitations := []Invitation{{GUID: "aaaa-1"}, {GUID: "bbbb-2"}, {GUID: "cccc-3"}}
	for _, s := range [][2]string{{"all", ""}, {"2", ""}, {"3,1,3", ""}, {"BBBB-2", ""}, {"", "1, 2\n"}, {"", "all"}, {"", ""}, {"0", ""}, {",,", ""}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, selection, answer string) {
		setStdin(t, answer)
		var selected []Invitation
		captureStdout(t, func() { selected, _ = selectInvitations(invitations, InvitationsAccept, selection) })
		checkSelection(t, invitations, selected)
	})
}

// Any content of a cache file, such as one edited by hand, is used or reported without a
// panic. A file that can't be used isn't overwritten, and -show-saved escapes what it shows.
func FuzzCacheFile(f *testing.F) {
	for _, s := range []string{`{}`, `{"a@example.com":{"auth_token":"authA"}}`, `null`, `[]`, `{"a@example.com":"x"}`,
		`{"a@example.com":{"auth_token":1}}`, `{"leak.user@example.com":{"key":{"private_key":"\u001b[2J"},"bikes":[{"frame_number":7}]}}`,
		"VMC2\x00\x00\x00\x01", "{", ""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		dir := filepath.Dir(useTempCache(t, ""))
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"tokens.json", "bikes.json", "customer_data.json"} {
			if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
				t.Fatal(err)
			}
		}

		entries, loadErr := tokenCache.loadAll(false)
		captureStdout(t, func() { saveTokenCache("new@example.com", "authN", "refreshN", "appN", false) })
		after, _ := os.ReadFile(filepath.Join(dir, "tokens.json"))
		if loadErr != nil && !bytes.Equal(after, content) {
			t.Error("cache that couldn't be read was overwritten")
		}
		if loadErr == nil {
			saved, err := tokenCache.loadAll(false)
			if err != nil {
				t.Fatalf("cache unreadable after saving: %v", err)
			}
			for email, tokens := range entries {
				if email != "new@example.com" && saved[email] != tokens {
					t.Errorf("tokens of %q lost", email)
				}
			}
			if saved["new@example.com"].AuthToken != "authN" {
				t.Error("new tokens not saved")
			}
		}

		defer SetRedaction(false, false)
		for _, redact := range []bool{false, true} {
			SetRedaction(redact, false)
			if out := captureStdout(t, func() { ShowSaved(leakEmail, false) }); unescaped(out) {
				t.Errorf("-show-saved output not escaped: %q", out)
			}
		}
	})
}

// Any encrypted cache is decrypted, or rejected, without a panic
func FuzzDecrypt(f *testing.F) {
	encrypted := encrypt([]byte(`{"a@example.com":{"auth_token":"authA"}}`), "secret")
	header := func(iterations uint32) []byte { return binary.BigEndian.AppendUint32([]byte(cacheMagic), iterations) }
	f.Add(encrypted)
	f.Add(encrypted[:len(encrypted)/2])
	f.Add(encrypted[cacheHeaderSize:]) // as without the header
	f.Add(header(0))
	f.Add(append(header(maxPBKDF2Iterations+1), make([]byte, 64)...))
	f.Add([]byte(cacheMagic))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Deriving the key from that many iterations takes too long for fuzzing
		if hasCacheHeader(data) {
			if n := binary.BigEndian.Uint32(data[len(cacheMagic):cacheHeaderSize]); n > pbkdf2Iterations && n <= maxPBKDF2Iterations {
				t.Skip()
			}
		}
		decrypt(data, "secret")
	})
}

// Whatever VanMoof answers, any status with any body (error pages, broken JSON, fields of
// the wrong type), every request returns a result or an error without a panic, and the
// output has nothing for a terminal to interpret. An error status is always an error.
func FuzzAPIResponses(f *testing.F) {
	for _, s := range []struct {
		status int
		body   string
	}{
		{200, `{}`}, {200, `null`}, {200, `[]`}, {200, `{"data":`}, {200, `{"data":{"uuid":7,"bikes":"x"}}`},
		{200, `{"data":{"uuid":"u","bikes":[{"id":1,"frameNumber":"BBBBBB00001AA","bleProfile":"ELECTRIFIED_2022"}],` +
			`"bikeDetails":[{"id":2,"frameNumber":"LKY\u001b0000002","bleProfile":"ELECTRIFIED_2018","key":{"encryptionKey":""}}]}}`},
		{200, `{"certificate":"AAAA"}`}, {200, `{"err":{"code":1}}`}, {200, `{"token":"x","refreshToken":"y"}`},
		{200, `{"invitations":[{"guid":"g","ownerName":"\u001b[2J","bikeName":"\u202e"}],"hash":"x"}`}, {200, `{"result":false}`},
		{200, `[{"content":"x"}]`}, {401, `{"error":"AuthenticationException"}`}, {404, "Not Found"}, {500, "<html>\x1b[2J</html>"}, {302, ""},
	} {
		f.Add(s.status, s.body)
	}
	f.Fuzz(func(t *testing.T, status int, body string) {
		if status < 100 || status > 599 {
			t.Skip()
		}
		useTempCache(t, "")
		t.Setenv("VANMOOF_PASSWORD", leakPassword)
		api := http.DefaultTransport
		http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return httpResponse(r, status, body), nil
		})
		defer func() { http.DefaultTransport = api }()

		// The library
		_, publicKey, _ := GenerateED25519()
		s := testSession()
		_, errBikes := s.Bikes()
		_, errUserID := s.UserID()
		_, errCert := s.RequestCertificate(fakeSA5, publicKey)
		_, errInvitations := s.Invitations()
		_, errAccept := s.AcceptInvitation(leakInviteGUID)
		errDecline := s.DeclineInvitation(leakInviteGUID)
		if status < 200 || status > 299 {
			for i, err := range []error{errBikes, errUserID, errCert, errInvitations, errAccept, errDecline} {
				if err == nil {
					t.Errorf("request %d: no error for HTTP %d", i, status)
				}
			}
		}

		// The command line tool, with debug output
		out := captureStdout(t, func() {
			opts := Options{BikeFilter: "all", Debug: true, NoCache: true}
			GetCert(leakEmail, opts)
			ShowKeys(leakEmail, ShowKeysAll, opts)
			Invitations(leakEmail, InvitationsAccept, "all", opts)
		})
		if unescaped(out) {
			t.Errorf("output not escaped: %q", out)
		}
	})
}
