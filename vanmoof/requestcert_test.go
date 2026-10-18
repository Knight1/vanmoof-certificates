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
		body := `{"err":"no certificate for this bike"}`
		if frame != "BBBBBB00002AA" {
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

	var err error
	out := captureStdout(t, func() {
		err = requestCertificates([]Bike{refused, wrong, good}, "", testSession(), &savedAccount{}, Options{BikeFilter: "all"})
	})
	if err == nil || err.Error() != "2 of 3 certificate(s) failed" {
		t.Errorf("err = %v, want 2 of 3 certificate(s) failed", err)
	}
	if !strings.Contains(out, "Certificate valid: BBBBBB00001AA") {
		t.Errorf("the valid certificate wasn't processed after the failed ones:\n%s", out)
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
