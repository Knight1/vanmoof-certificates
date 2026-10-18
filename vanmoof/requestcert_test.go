package vanmoof

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// requestCertificates goes on with the other bikes when one fails, but reports it
func TestRequestCertificatesReportsFailures(t *testing.T) {
	ca := trustTestCA(t)
	old := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = old })
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var req CertificateRequest
		json.NewDecoder(r.Body).Decode(&req)
		frame := strings.Split(r.URL.Path, "/")[2]
		var body string
		switch frame {
		case "BBBBBB00002AA":
			body = `{"err":"no certificate for this bike"}`
		case "BBBBBB00004AA":
			body = "not JSON"
		case "BBBBBB00005AA":
			body = `{"certificate":7}`
		default:
			// The certificate for BBBBBB00003AA is for another bike
			if frame == "BBBBBB00003AA" {
				frame = "BBBBBB00009AA"
			}
			fields := testCertFields(frame)
			fields["p"], _ = base64.StdEncoding.DecodeString(req.PublicKey)
			body = `{"certificate":"` + testCert(t, ca, fields) + `"}`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})

	good := Bike{BikeID: 1, FrameNumber: "BBBBBB00001AA", BleProfile: "ELECTRIFIED_2022"}
	refused := Bike{BikeID: 2, FrameNumber: "BBBBBB00002AA", BleProfile: "ELECTRIFIED_2022"}
	wrong := Bike{BikeID: 3, FrameNumber: "BBBBBB00003AA", BleProfile: "ELECTRIFIED_2022"}
	garbled := Bike{BikeID: 4, FrameNumber: "BBBBBB00004AA", BleProfile: "ELECTRIFIED_2022"}
	without := Bike{BikeID: 5, FrameNumber: "BBBBBB00005AA", BleProfile: "ELECTRIFIED_2022"}

	var err error
	out := captureStdout(t, func() {
		err = requestCertificates([]Bike{refused, wrong, garbled, without, good}, "", testSession(), &savedAccount{}, Options{BikeFilter: "all"})
	})
	if err == nil || err.Error() != "4 of 5 certificate(s) failed" {
		t.Errorf("err = %v, want 4 of 5 certificate(s) failed", err)
	}
	for _, want := range []string{"Certificate error: ", "Failed to parse certificate response: ", "Certificate response missing 'certificate' field",
		"Certificate valid: BBBBBB00001AA"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q: the valid certificate has to be processed after the failed ones\n%s", want, out)
		}
	}

	captureStdout(t, func() {
		err = requestCertificates([]Bike{good}, "", testSession(), &savedAccount{}, Options{BikeFilter: "all"})
	})
	if err != nil {
		t.Errorf("err = %v for a valid certificate", err)
	}
}

// A token response without a token is an error, so no empty token is used or cached:
// logging in goes on to the next way, as when the server rejects a token
func TestEmptyTokensAreErrors(t *testing.T) {
	useTempCache(t, "")
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	fakeVanMoof(t)
	captureStdout(t, func() { saveTokenCache(leakEmail, leakAuthToken, leakRefresh, expiredJWT(), false) })
	// 200 OK, but without a token
	failRequests(t, http.StatusOK, "/v8/authenticate", "/v8/token", "/v8/getApplicationToken")

	if _, _, err := authenticate(leakEmail, leakPassword, false); err == nil {
		t.Error("authenticate: no error")
	}
	if _, _, err := refreshAuthToken(leakRefresh, false); err == nil {
		t.Error("refreshAuthToken: no error")
	}
	if _, err := getApplicationToken(leakAuthToken, false); err == nil {
		t.Error("getApplicationToken: no error")
	}

	// The command line tool, renewing the cached app token
	var tokens Tokens
	var err error
	captureStdout(t, func() { tokens, _, err = resolveTokens(leakEmail, "", false, false, false) })
	if err == nil {
		t.Errorf("resolveTokens = %+v, want an error", tokens)
	}

	// The library, renewing expired tokens
	s := Resume(Tokens{AuthToken: expiredJWT(), AppToken: expiredJWT(), RefreshToken: leakRefresh})
	if _, err := s.UserID(); !errors.Is(err, ErrLoginRequired) {
		t.Errorf("UserID: err = %v, want ErrLoginRequired", err)
	}
}

// countRequests counts the requests to each path from now on: it returns a function that
// returns the counts and starts over
func countRequests(t *testing.T) func() map[string]int {
	t.Helper()
	var mu sync.Mutex
	counts := make(map[string]int)
	api := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		counts[r.URL.Path]++
		mu.Unlock()
		return api.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = api })
	return func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		c := counts
		counts = make(map[string]int)
		return c
	}
}

// Cached tokens are used while they're valid. An expired app token is renewed with the
// auth token, an expired auth token with the refresh token, keeping a rotated one, and
// the password is only the last resort.
func TestResolveTokens(t *testing.T) {
	useTempCache(t, "")
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	fakeVanMoof(t)
	requests := countRequests(t)
	valid := Tokens{AuthToken: leakAuthToken, AppToken: leakAppToken, RefreshToken: leakRefresh}

	tests := []struct {
		name             string
		cached           *Tokens // nil for none
		skipCached       bool    // the server rejected the cached tokens
		noCache          bool
		want             Tokens
		fromCache        bool
		requests         map[string]int
		cachedAfterwards Tokens
	}{
		{"valid", &valid, false, false, valid, true, map[string]int{}, valid},
		{"app token expired", &Tokens{AuthToken: leakAuthToken, AppToken: expiredJWT(), RefreshToken: leakRefresh}, false, false,
			valid, true, map[string]int{"/v8/getApplicationToken": 1}, valid},
		{"auth token expired", &Tokens{AuthToken: expiredJWT(), AppToken: expiredJWT(), RefreshToken: leakRefresh}, false, false,
			Tokens{AuthToken: leakAuthToken, AppToken: leakAppToken, RefreshToken: leakRotated}, false,
			map[string]int{"/v8/token": 1, "/v8/getApplicationToken": 1}, Tokens{AuthToken: leakAuthToken, AppToken: leakAppToken, RefreshToken: leakRotated}},
		{"rejected by the server", &valid, true, false,
			Tokens{AuthToken: leakAuthToken, AppToken: leakAppToken, RefreshToken: leakRotated}, false,
			map[string]int{"/v8/token": 1, "/v8/getApplicationToken": 1}, Tokens{AuthToken: leakAuthToken, AppToken: leakAppToken, RefreshToken: leakRotated}},
		{"none cached", nil, false, false, valid, false,
			map[string]int{"/v8/authenticate": 1, "/v8/getApplicationToken": 1}, valid},
		{"-no-cache", &Tokens{AuthToken: "cachedAuth", AppToken: "cachedApp"}, false, true, valid, false,
			map[string]int{"/v8/authenticate": 1, "/v8/getApplicationToken": 1}, Tokens{AuthToken: "cachedAuth", AppToken: "cachedApp"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, _ := tokenCachePath()
			os.Remove(path)
			if tt.cached != nil {
				captureStdout(t, func() { tokenCache.save(leakEmail, *tt.cached, false) })
			}
			requests()

			var tokens Tokens
			var fromCache bool
			var err error
			captureStdout(t, func() { tokens, fromCache, err = resolveTokens(leakEmail, "", tt.skipCached, false, tt.noCache) })
			if err != nil || tokens != tt.want || fromCache != tt.fromCache {
				t.Errorf("resolveTokens = %+v, %v, %v; want %+v, %v", tokens, fromCache, err, tt.want, tt.fromCache)
			}
			if got := requests(); !maps.Equal(got, tt.requests) {
				t.Errorf("requests %v, want %v", got, tt.requests)
			}
			if cached, _ := tokenCache.load(leakEmail, false); cached != tt.cachedAfterwards {
				t.Errorf("cached afterwards %+v, want %+v", cached, tt.cachedAfterwards)
			}
		})
	}
}

// Cached tokens the server rejects before they expire (revoked, e.g. after a password
// change) are replaced: login logs in again, with the refresh token first
func TestLoginRetriesRejectedTokens(t *testing.T) {
	useTempCache(t, "")
	fakeVanMoof(t)
	captureStdout(t, func() { saveTokenCache(leakEmail, leakAuthToken, leakRefresh, leakAppToken, false) })
	var rejected atomic.Bool
	api := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v8/getCustomerData" && rejected.CompareAndSwap(false, true) {
			return httpResponse(r, http.StatusUnauthorized, `{"error":"AuthenticationException"}`), nil
		}
		return api.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = api })

	var s *Session
	var data *CustomerData
	var err error
	out := captureStdout(t, func() { s, data, err = login(leakEmail, false, false) })
	if err != nil || data.Data.UUID != leakUUID || !strings.Contains(out, "Cached tokens were rejected by the server") {
		t.Fatalf("login: %v\n%s", err, out)
	}
	if tokens := s.Tokens(); tokens.RefreshToken != leakRotated {
		t.Errorf("tokens %+v, want the refreshed ones", tokens)
	}

	// Rejected again, it gives up
	failRequests(t, http.StatusUnauthorized, "/v8/getCustomerData")
	captureStdout(t, func() { _, _, err = login(leakEmail, false, false) })
	if err == nil || !strings.Contains(err.Error(), "failed to get customer data") {
		t.Errorf("err = %v", err)
	}

	// and when it can't log in again, without a refresh token or password that works
	failRequests(t, http.StatusUnauthorized, "/v8/token")
	typePassword(t, "", errors.New("no terminal"))
	captureStdout(t, func() { _, _, err = login(leakEmail, false, false) })
	if err == nil || !strings.Contains(err.Error(), "authentication failed: error reading password: no terminal") {
		t.Errorf("err = %v", err)
	}
}

// typePassword makes the password prompt read password, or fail with err, for the rest of
// the test
func typePassword(t *testing.T, password string, err error) {
	t.Helper()
	old := readPassword
	readPassword = func(int) ([]byte, error) { return []byte(password), err }
	t.Cleanup(func() { readPassword = old })
}

// Without cached tokens or VANMOOF_PASSWORD, logging in asks for the password, and fails
// without one
func TestPasswordPrompt(t *testing.T) {
	useTempCache(t, "")
	t.Setenv("VANMOOF_PASSWORD", "")
	fakeVanMoof(t)
	tests := []struct {
		name, password string
		readErr        error
		err            string // the error, or "" for none
	}{
		{"typed", leakPassword, nil, ""},
		{"none", "", nil, "password required"},
		{"unreadable", "", errors.New("no terminal"), "error reading password: no terminal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typePassword(t, tt.password, tt.readErr)
			var tokens Tokens
			var err error
			out := captureStdout(t, func() { tokens, _, err = resolveTokens(leakEmail, "", false, false, true) })
			if !strings.HasPrefix(out, "Enter VanMoof password: ") || (err == nil) != (tt.err == "") || (err != nil && err.Error() != tt.err) {
				t.Errorf("err = %v, want %q\n%s", err, tt.err, out)
			}
			if err == nil && tokens.AppToken != leakAppToken {
				t.Errorf("tokens %+v", tokens)
			}
		})
	}
}

// With -debug, resolveTokens says which of the cached tokens it tried, and why it went on
// to the next: here as getting a new app token or a refresh fails. A refresh that doesn't
// rotate the refresh token keeps the old one.
func TestResolveTokensFallbacks(t *testing.T) {
	useTempCache(t, "")
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	fakeVanMoof(t)
	valid := Tokens{AuthToken: leakAuthToken, AppToken: leakAppToken, RefreshToken: leakRefresh}

	tests := []struct {
		name   string
		cached Tokens
		fail   string // the requests that fail
		want   Tokens // zero for an error
		debug  []string
	}{
		{"no app token at all", Tokens{AuthToken: leakAuthToken, AppToken: expiredJWT(), RefreshToken: leakRefresh}, "/v8/getApplicationToken", Tokens{}, []string{
			"App token expired, refreshing with cached auth token", "Failed to get app token with cached auth token: HTTP 500",
			"Auth token expired or rejected, trying refresh token", "Failed to get app token after refresh: HTTP 500",
			"All cached tokens expired or rejected, need password"}},
		{"refresh token rejected", Tokens{AuthToken: expiredJWT(), RefreshToken: leakRefresh}, "/v8/token", valid, []string{
			"Auth token expired or rejected, trying refresh token", "Refresh token failed: HTTP 500", "All cached tokens expired or rejected, need password"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			captureStdout(t, func() { tokenCache.save(leakEmail, tt.cached, false) })
			failRequests(t, http.StatusInternalServerError, tt.fail)
			var tokens Tokens
			var err error
			out := captureStdout(t, func() { tokens, _, err = resolveTokens(leakEmail, "", false, true, false) })
			if tokens != tt.want || (err == nil) != (tt.want != Tokens{}) {
				t.Errorf("resolveTokens = %+v, %v; want %+v", tokens, err, tt.want)
			}
			for _, line := range tt.debug {
				if !strings.Contains(out, "[DEBUG] "+line) {
					t.Errorf("output lacks %q:\n%s", line, out)
				}
			}
		})
	}

	captureStdout(t, func() { tokenCache.save(leakEmail, Tokens{AuthToken: expiredJWT(), RefreshToken: leakRefresh}, false) })
	api := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v8/token" {
			return httpResponse(r, http.StatusOK, `{"token":"`+leakAuthToken+`"}`), nil
		}
		return api.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = api })
	var tokens Tokens
	var err error
	captureStdout(t, func() { tokens, _, err = resolveTokens(leakEmail, "", false, false, false) })
	if err != nil || tokens != valid {
		t.Errorf("after a refresh without a new refresh token: resolveTokens = %+v, %v; want %+v", tokens, err, valid)
	}
}

// requestCertificates requests the certificates for the bikes picked (none is no error),
// and for the public key given with -pubkey, if any, instead of the key pair
func TestRequestCertificatesOptions(t *testing.T) {
	fakeVanMoof(t)
	_, publicKey, _ := GenerateED25519()
	tests := []struct {
		name, stdin string
		opts        Options
		err         string // part of the error, or "" for none
		output      string // part of the output
	}{
		{"none picked", "", Options{BikeFilter: "1"}, "", "No bikes selected"},
		{"nothing to pick from", "", Options{BikeFilter: "ask"}, "failed to read input", "Enter bike numbers"},
		{"-pubkey", "", Options{BikeFilter: "all", PublicKey: publicKey, Debug: true}, "",
			"[DEBUG] Using supplied public key for certificate requests: " + publicKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setStdin(t, tt.stdin)
			account := savedAccount{}
			var err error
			out := captureStdout(t, func() { err = requestCertificates([]Bike{fakeSA5}, "", testSession(), &account, tt.opts) })
			if (err == nil) != (tt.err == "") || (err != nil && !strings.Contains(err.Error(), tt.err)) || !strings.Contains(out, tt.output) {
				t.Errorf("err = %v, want %q; output lacks %q?\n%s", err, tt.err, tt.output, out)
			}
			if account.Key != nil || strings.Contains(out, "Privkey") {
				t.Errorf("a key pair made, but not needed:\n%s", out)
			}
		})
	}
}

// Debug output names the model of each BLE profile it knows, and calls the others unknown
func TestDebugProfiles(t *testing.T) {
	out := captureStdout(t, func() {
		debugPrintBikeProfiles([]Bike{{FrameNumber: "BBBBBB00001AA", BleProfile: "ELECTRIFIED_2022"}, {FrameNumber: "BBBBBB00002AA", BleProfile: "ELECTRIFIED_2030"}})
		debugPrintVehicleAccessProfiles([]VehicleAccess{{VehicleID: "AAAAA000001AA", BleProfile: "ELECTRIFIED_2030"}})
	})
	for _, want := range []string{"BBBBBB00001AA: ELECTRIFIED_2022 (SA5)", "BBBBBB00002AA: ELECTRIFIED_2030 (unknown)", "AAAAA000001AA: ELECTRIFIED_2030 (unknown)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// A bike that's both the account's own and shared with it is listed once, as its own
func TestAddSharedBikes(t *testing.T) {
	owned := []Bike{{BikeID: 1, Name: "mine", FrameNumber: "BBBBBB00001AA", BleProfile: "ELECTRIFIED_2022"}}
	shared := []VehicleAccess{
		{VehicleID: "BBBBBB00001AA", Name: "also mine"},
		{VehicleID: "AAAAA000002AA", Name: "theirs", BleProfile: "ELECTRIFIED_2025", OwnerName: "Owner"},
	}
	want := []Bike{owned[0], {Name: "theirs", FrameNumber: "AAAAA000002AA", BleProfile: "ELECTRIFIED_2025", Owner: "Owner"}}
	if got := addSharedBikes(owned, shared); !slices.Equal(got, want) {
		t.Errorf("addSharedBikes = %+v, want %+v", got, want)
	}
}

// Tokens the session renews during a run are cached, so the next run doesn't renew them
// again
func TestRenewedTokensAreCached(t *testing.T) {
	useTempCache(t, "")
	fakeVanMoof(t)
	revoked := leakJWT("RevokedAppSignature0123456789abcdefghijklm") // not expired, but rejected
	captureStdout(t, func() { saveTokenCache(leakEmail, leakAuthToken, leakRefresh, revoked, false) })
	api := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/create_certificate") && r.Header.Get("Authorization") == "Bearer "+revoked {
			return httpResponse(r, http.StatusUnauthorized, `{"error":"token revoked"}`), nil
		}
		return api.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = api })

	out := getCert(t, Options{BikeFilter: "all", CleartextKeys: true})
	if !strings.Contains(out, "Certificate valid") {
		t.Errorf("no certificate after renewing the token:\n%s", out)
	}
	if cached := loadTokenCache(leakEmail, false); cached == nil || cached.AppToken != leakAppToken {
		t.Errorf("cached tokens %+v, want the renewed app token", cached)
	}
}
