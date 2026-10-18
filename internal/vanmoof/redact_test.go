package vanmoof

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// setRedaction sets the redaction mode for the duration of the test
func setRedaction(t *testing.T, redact, everything bool) {
	t.Helper()
	SetRedaction(redact, everything)
	t.Cleanup(func() { SetRedaction(false, false) })
}

func TestRedactJSON(t *testing.T) {
	body := `{"token":"tokVALUE","refreshToken":"refVALUE","data":{"uuid":"uuidVALUE","bleProfile":"ELECTRIFIED_2022",` +
		`"frameNumber":"ABCDEF12345GH","key":{"encryptionKey":"bleKeyVALUE","passcode":""},"err":"no bike for x@example.com"}}`
	tests := []struct {
		name             string
		redact, all      bool
		want, wantAbsent []string
	}{
		{"debug hides secrets", false, false,
			[]string{`"token":"[REDACTED]"`, `"refreshToken":"[REDACTED]"`, `"encryptionKey":"[REDACTED]"`, `"passcode":""`, "uuidVALUE", "ABCDEF12345GH"},
			[]string{"tokVALUE", "refVALUE", "bleKeyVALUE"}},
		{"-redact hides all but harmless fields", true, false,
			[]string{`"bleProfile":"ELECTRIFIED_2022"`, `"frameNumber":"LLLLLLDDDDDLL"`, `"uuid":"[REDACTED]"`, `"err":"no bike for [REDACTED]"`},
			[]string{"tokVALUE", "refVALUE", "bleKeyVALUE", "uuidVALUE", "ABCDEF12345GH", "x@example.com"}},
		{"-show-everything hides nothing", false, true, []string{body}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRedaction(t, tt.redact, tt.all)
			got := redactJSON(body)
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("%s lacks %s", got, w)
				}
			}
			for _, w := range tt.wantAbsent {
				if strings.Contains(got, w) {
					t.Errorf("%s still contains %s", got, w)
				}
			}
		})
	}
}

func TestScrubText(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	in := "GET /external/riders/1eaf0000-0000-4000-8000-00000000beef/vehicles for x@example.com: bike 987654, " +
		"frame ABCDEF12345GH, MAC C0:FF:EE:00:00:01, key 1eaf1eaf1eaf1eaf1eaf1eaf1eaf1eaf, " +
		"token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl, cache " + filepath.Join(home, ".vanmoof-certificates")

	if got := ScrubText(in); got != in {
		t.Errorf("ScrubText changed text without -redact: %s", got)
	}

	setRedaction(t, true, false)
	got := ScrubText(in)
	for _, leak := range []string{"1eaf0000", "x@example.com", "987654", "ABCDEF12345GH", "C0:FF:EE", "1eaf1eaf", "eyJ", home} {
		if strings.Contains(got, leak) {
			t.Errorf("ScrubText kept %q: %s", leak, got)
		}
	}
	for _, want := range []string{"bike DDDDDD", "frame LLLLLLDDDDDLL", "cache ~"} {
		if !strings.Contains(got, want) {
			t.Errorf("ScrubText output lacks %q: %s", want, got)
		}
	}
}

func TestPrintable(t *testing.T) {
	tests := []struct{ in, want string }{
		{"LEAKYA12345ZZ", "LEAKYA12345ZZ"},
		{"Bike\x1b[2K\rCertificate valid", `Bike\x1b[2K\x0dCertificate valid`},
		{"evil\u202eknab", `evil\u202eknab`},
		{"tab\tnew\nline", `tab\x09new\x0aline`},
		{"bad \xff byte", "bad � byte"},
		{"Grüße 🚲", "Grüße 🚲"},
	}
	for _, tt := range tests {
		if got := printable(tt.in); got != tt.want {
			t.Errorf("printable(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// Control characters from a certificate or the API don't reach the terminal as such:
// they'd let a crafted certificate rewrite "Certificate INVALID" into something else
func TestOutputEscapesControlCharacters(t *testing.T) {
	hasRaw := func(out string) bool {
		return strings.ContainsFunc(out, func(r rune) bool { return r != '\n' && needsEscape(r) })
	}

	fields := testCertFields("AAAAAA00001AA")
	fields["f"] = "AAAAAA00001AA\x1b[2K\rCertificate valid"
	cert := testCert(t, nil, fields)
	for _, debug := range []bool{false, true} {
		if out := captureStdout(t, func() { ProcessCertificate(cert, "", "", debug) }); hasRaw(out) {
			t.Errorf("debug=%v: output has raw control characters: %q", debug, out)
		}
	}

	old := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = old })
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("bad\x1b[2Jrequest")), Request: r}, nil
	})
	bikes := []BikeData{{BikeID: 1, Name: "My\x1b[31m bike\u202e", FrameNumber: "BBBBBB00001AA", BleProfile: "ELECTRIFIED_2022"}}
	out := captureStdout(t, func() { requestCertificates(bikes, "", "app", "all", "", false) })
	if hasRaw(out) || !strings.Contains(out, `HTTP 400: bad\x1b[2Jrequest`) {
		t.Errorf("output: %q", out)
	}
}

// Values of the fake VanMoof account. Each is unique, to find any of them in the output.
const (
	leakEmail      = "leak.user@example.com"
	leakPassword   = "LeakPassword42"
	leakRefresh    = "LeakRefreshToken42"
	leakUUID       = "1eaf0000-0000-4000-8000-00000000beef"
	leakName       = "Leaky McLeakface"
	leakPhone      = "+31600000042"
	leakSA5Name    = "LeakySA5"
	leakS3Name     = "LeakyS3"
	leakS2Name     = "LeakyS2"
	leakSharedName = "LeakyShared"
	leakRiderName  = "LeakyRider"
	leakOwnerName  = "LeakyOwner"
	leakOwnerEmail = "leak.owner@example.com"
	leakOwnerUUID  = "1eaf0000-0000-4000-8000-0000000000aa"
	leakMAC        = "C0:FF:EE:00:00:01"
	leakMAC2       = "C0:FF:EE:00:00:02"
	leakMAC3       = "C0:FF:EE:00:00:03"
	leakBLEKey     = "1eaf1eaf1eaf1eaf1eaf1eaf1eaf1eaf"
	leakPasscode   = "LeakPasscode42"
	leakMessage    = "LeakMessageContent42"
	leakSA5Frame   = "LEAKYA12345ZZ"
	leakS6Frame    = "LEAKY123456ZZ"
	leakS3Frame    = "LKY7654321"
	leakS2Frame    = "LKY7654322"
	leakOtherFrame = "LEAKYB54321ZZ"
	leakECU        = "LeakECU42"
	leakSA5ID      = 987654
	leakS3ID       = 876543
	leakS2ID       = 765432
)

func leakJWT(signature string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d,"sub":%q,"email":%q}`, time.Now().Add(time.Hour).Unix(), leakUUID, leakEmail)))
	return header + "." + claims + "." + signature
}

var (
	// 43 characters, the base64url length of an HS256 signature
	leakAuthToken = leakJWT("LeakAuthSignature0123456789abcdefghijklmnop")
	leakAppToken  = leakJWT("LeakAppSignature0123456789abcdefghijklmnopq")
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fakeVanMoof serves the fake account's data for every API the tool calls, instead of
// the network, and records the certificates and public keys it hands out.
func fakeVanMoof(t *testing.T) (certs, pubKeys *[]string) {
	certs, pubKeys = new([]string), new([]string)
	ca := trustTestCA(t)
	userID, _ := hex.DecodeString(strings.ReplaceAll(leakUUID, "-", ""))
	customerData, _ := json.Marshal(map[string]interface{}{"data": map[string]interface{}{
		"uuid": leakUUID, "name": leakName, "email": leakEmail, "phone": leakPhone,
		"bikes": []map[string]interface{}{
			{"id": leakSA5ID, "name": leakSA5Name, "frameNumber": leakSA5Frame, "frameSerial": leakSA5Frame, "mainEcuSerial": leakECU, "bleProfile": "ELECTRIFIED_2022"},
			{"id": leakS3ID, "name": leakS3Name, "frameNumber": leakS3Frame, "bleProfile": "ELECTRIFIED_2021"},
			{"id": leakS2ID, "name": leakS2Name, "frameNumber": leakS2Frame, "bleProfile": "ELECTRIFIED_2018"},
		},
		"bikeDetails": []map[string]interface{}{
			{"id": leakSA5ID, "name": leakSA5Name, "frameNumber": leakSA5Frame, "macAddress": leakMAC, "bleProfile": "ELECTRIFIED_2022", "key": map[string]string{"encryptionKey": leakBLEKey, "passcode": leakPasscode}},
			{"id": leakS3ID, "name": leakS3Name, "frameNumber": leakS3Frame, "macAddress": leakMAC2, "bleProfile": "ELECTRIFIED_2021", "key": map[string]string{"encryptionKey": leakBLEKey, "passcode": leakPasscode}},
			{"id": leakS2ID, "name": leakS2Name, "frameNumber": leakS2Frame, "macAddress": leakMAC3, "bleProfile": "ELECTRIFIED_2018", "key": map[string]string{"encryptionKey": ""}},
		},
	}})
	vehicles, _ := json.Marshal(map[string]interface{}{"rider_id": leakUUID, "vehicle_access": []map[string]interface{}{{
		"vehicle_id": leakS6Frame, "role": "guest", "rider_name": leakRiderName, "rider_email": leakEmail, "name": leakSharedName,
		"ble_profile": "ELECTRIFIED_2025", "ble_id": leakMAC3, "owner_id": leakOwnerUUID, "owner_name": leakOwnerName, "owner_email": leakOwnerEmail,
	}}})

	old := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body string
		switch p := r.URL.Path; {
		case p == "/v8/authenticate":
			body = fmt.Sprintf(`{"token":%q,"refreshToken":%q}`, leakAuthToken, leakRefresh)
		case p == "/v8/getApplicationToken":
			body = fmt.Sprintf(`{"token":%q}`, leakAppToken)
		case p == "/v8/getBikeSharingInvitations":
			body = fmt.Sprintf(`{"invitations":[{"name":%q,"email":%q}],"hash":"x"}`, leakOwnerName, leakOwnerEmail)
		case p == "/v8/getCustomerData":
			body = string(customerData)
		case strings.HasPrefix(p, "/v8/getBikeMessages/"):
			body = fmt.Sprintf(`[{"content":%q}]`, leakMessage)
		case p == "/external/riders/"+leakUUID+"/vehicles":
			body = string(vehicles)
		case strings.HasSuffix(p, "/create_certificate"):
			var req CertificateRequest
			json.NewDecoder(r.Body).Decode(&req)
			pub, _ := base64.StdEncoding.DecodeString(req.PublicKey)
			frame := strings.Split(p, "/")[2]
			fields := testCertFields(frame)
			fields["u"], fields["p"] = userID, pub
			key := ca
			if frame == leakS6Frame {
				key = nil // no S6 signing key known
			}
			cert := testCert(t, key, fields)
			*certs, *pubKeys = append(*certs, cert), append(*pubKeys, req.PublicKey)
			body = fmt.Sprintf(`{"certificate":%q}`, cert)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = old })
	return certs, pubKeys
}

// runEverything runs every flow that prints account data, with debug output: requesting
// certificates (logging in, then with cached tokens), showing keys, checking a certificate
// offline against the wrong frame number, and an unreadable token cache.
func runEverything(t *testing.T) (out string, certs, pubKeys []string) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("VANMOOF_CACHE_KEY", "")
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	certsP, pubKeysP := fakeVanMoof(t)

	out = captureStdout(t, func() {
		for i := 0; i < 2; i++ {
			if err := GetCert(leakEmail, "all", "", true, false); err != nil {
				t.Errorf("GetCert: %v", err)
			}
		}
		if err := ShowKeys(leakEmail, ShowKeysAll, "all", "", true, false); err != nil {
			t.Errorf("ShowKeys: %v", err)
		}
		ProcessCertificate((*certsP)[0], (*pubKeysP)[0], leakOtherFrame, true)

		path, _ := tokenCachePath()
		os.WriteFile(path, []byte("unreadable"), 0600)
		loadTokenCache(leakEmail, true)
	})
	return out, *certsP, *pubKeysP
}

var (
	leakSecrets = []string{leakPassword, leakRefresh, leakAuthToken, leakAppToken, "LeakAuthSignature", "LeakAppSignature",
		leakBLEKey, leakPasscode, leakMessage}
	leakPersonal = []string{leakEmail, leakUUID, strings.ReplaceAll(leakUUID, "-", ""), leakName, leakPhone,
		leakSA5Name, leakS3Name, leakS2Name, leakSharedName, leakRiderName, leakOwnerName, leakOwnerEmail, leakOwnerUUID,
		leakMAC, leakMAC2, leakMAC3, leakSA5Frame, leakS6Frame, leakS3Frame, leakS2Frame, leakOtherFrame, leakECU,
		fmt.Sprint(leakSA5ID), fmt.Sprint(leakS3ID), fmt.Sprint(leakS2ID)}
	privKeyLine = regexp.MustCompile(`Privkey = (\S+)`)
)

func TestRedactLeaks(t *testing.T) {
	t.Run("-debug hides secrets", func(t *testing.T) {
		setRedaction(t, false, false)
		out, _, _ := runEverything(t)
		for _, s := range leakSecrets {
			// -show-keys shows the BLE key on purpose, but only there
			if s == leakBLEKey {
				if n, shown := strings.Count(out, s), strings.Count(out, "bleSecret: "+s); shown == 0 || n != shown {
					t.Errorf("BLE key in the output %d times, %d of them as bleSecret", n, shown)
				}
				continue
			}
			if strings.Contains(out, s) {
				t.Errorf("debug output contains secret %q", s)
			}
		}
		if !strings.Contains(out, leakSA5Frame) {
			t.Error("debug output lacks the frame number")
		}
	})

	t.Run("-debug -redact hides secrets and personal data", func(t *testing.T) {
		setRedaction(t, true, false)
		out, certs, pubKeys := runEverything(t)
		home, _ := os.UserHomeDir()
		for _, s := range append(append(append(append([]string{home}, leakSecrets...), leakPersonal...), certs...), pubKeys...) {
			if strings.Contains(out, s) {
				t.Errorf("redacted output contains %q", s)
			}
		}
		for _, m := range privKeyLine.FindAllStringSubmatch(out, -1) {
			if m[1] != redacted {
				t.Errorf("redacted output contains a private key: %s", m[0])
			}
		}
		for _, want := range []string{"Frame number: LLLLLLDDDDDLL", "bleSecret: [REDACTED]", "ELECTRIFIED_2025", "~"} {
			if !strings.Contains(out, want) {
				t.Errorf("redacted output lacks %q", want)
			}
		}
	})

	t.Run("-debug -show-everything hides nothing", func(t *testing.T) {
		setRedaction(t, false, true)
		out, _, _ := runEverything(t)
		for _, s := range []string{leakRefresh, leakBLEKey, leakMessage, leakEmail} {
			if !strings.Contains(out, s) {
				t.Errorf("output lacks %q", s)
			}
		}
		if strings.Contains(out, leakPassword) {
			t.Error("output contains the password")
		}
	})
}
