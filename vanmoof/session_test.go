package vanmoof

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// expiredJWT is a token of the fake account that expired an hour ago
func expiredJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(-time.Hour).Unix())))
	return header + "." + claims + ".ExpiredSignature0123456789abcdefghijklmnopq"
}

func httpResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

// failRequests makes requests to paths starting with one of prefixes fail with status
func failRequests(t *testing.T, status int, prefixes ...string) {
	api := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		for _, p := range prefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				return httpResponse(r, status, `{"error":"failed"}`), nil
			}
		}
		return api.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = api })
}

var fakeSA5 = Bike{BikeID: leakSA5ID, FrameNumber: leakSA5Frame, BleProfile: "ELECTRIFIED_2022"}

// The library API end to end, as in the package example
func TestSession(t *testing.T) {
	fakeVanMoof(t)
	s, err := Login(leakEmail, leakPassword)
	if err != nil {
		t.Fatal(err)
	}
	if tokens := s.Tokens(); tokens != (Tokens{AuthToken: leakAuthToken, AppToken: leakAppToken, RefreshToken: leakRefresh}) {
		t.Errorf("Tokens() = %+v", tokens)
	}
	userID, err := s.UserID()
	if err != nil || userID != leakUUID {
		t.Errorf("UserID() = %q, %v", userID, err)
	}
	bikes, err := s.Bikes()
	if err != nil {
		t.Fatal(err)
	}

	// The 3 own bikes, then the shared S6; the SA5 and the S6 use certificates
	var certModels []string
	for _, b := range bikes {
		if b.UsesCertificates() {
			certModels = append(certModels, b.Model())
		}
	}
	if len(bikes) != 4 || strings.Join(certModels, ",") != "SA5,S6" || bikes[3].Name != leakSharedName || bikes[3].Owner != leakOwnerName {
		t.Fatalf("Bikes() = %+v", bikes)
	}

	_, publicKey, err := GenerateED25519()
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range bikes {
		if !b.UsesCertificates() {
			continue
		}
		cert, err := s.RequestCertificate(b, publicKey)
		if err != nil {
			t.Fatalf("RequestCertificate(%s): %v", b.Model(), err)
		}
		res := CheckCertificate(cert, Expect{PublicKey: publicKey, Bike: &bikes[i], UserID: userID, Bikes: bikes})
		if !res.Valid || !res.BikeVerified || !res.PublicKeyVerified || !res.UserIDVerified || res.MatchedBike != &bikes[i] ||
			res.FrameModule != b.FrameNumber || res.AccessLevel() != "Owner" || !res.Expires.After(time.Now()) {
			t.Errorf("%s: CheckCertificate = %+v", b.Model(), res)
		}
		// The fake signs SA5 certificates with a test key it trusts; no S6 key is known yet
		if want := b.Model() == "SA5"; res.SignatureVerified != want {
			t.Errorf("%s: SignatureVerified = %v, want %v", b.Model(), res.SignatureVerified, want)
		}
	}

	if res := CheckCertificate("not a certificate", Expect{}); res.Valid || len(res.Errors) == 0 {
		t.Errorf("CheckCertificate(garbage) = %+v", res)
	}
}

// Unlike the command line tool, the library returns its results and prints nothing
func TestSessionPrintsNothing(t *testing.T) {
	fakeVanMoof(t)
	_, publicKey, _ := GenerateED25519()
	var err error
	out := captureStdout(t, func() {
		var s *Session
		if s, err = Login(leakEmail, leakPassword); err != nil {
			return
		}
		var bikes []Bike
		if bikes, err = s.Bikes(); err != nil {
			return
		}
		for i, b := range bikes {
			if !b.UsesCertificates() {
				continue
			}
			var cert string
			if cert, err = s.RequestCertificate(b, publicKey); err != nil {
				return
			}
			CheckCertificate(cert, Expect{PublicKey: publicKey, Bike: &bikes[i], Bikes: bikes})
		}
		// Renewing expired tokens
		_, err = Resume(Tokens{AuthToken: expiredJWT(), AppToken: expiredJWT(), RefreshToken: leakRefresh}).UserID()
	})
	if err != nil {
		t.Fatal(err)
	}
	if out != "" {
		t.Errorf("printed:\n%s", out)
	}
}

func TestSessionBikesWithoutSharedOnes(t *testing.T) {
	fakeVanMoof(t)
	failRequests(t, http.StatusInternalServerError, "/external/riders/")
	bikes, err := testSession().Bikes()
	if !errors.Is(err, ErrSharedBikes) || len(bikes) != 3 {
		t.Errorf("Bikes() = %d bikes, %v; want the 3 own ones and ErrSharedBikes", len(bikes), err)
	}
}

func TestSessionRenewsTokens(t *testing.T) {
	fakeVanMoof(t)
	_, publicKey, _ := GenerateED25519()

	// An expired app token is renewed with the auth token
	s := Resume(Tokens{AuthToken: leakAuthToken, AppToken: expiredJWT(), RefreshToken: leakRefresh})
	if _, err := s.RequestCertificate(fakeSA5, publicKey); err != nil {
		t.Fatal(err)
	}
	if got := s.Tokens().AppToken; got != leakAppToken {
		t.Errorf("app token after renewing = %q", got)
	}

	// An expired auth token is renewed with the refresh token, keeping the rotated one
	s = Resume(Tokens{AuthToken: expiredJWT(), AppToken: expiredJWT(), RefreshToken: leakRefresh})
	if _, err := s.UserID(); err != nil {
		t.Fatal(err)
	}
	if got := s.Tokens(); got != (Tokens{AuthToken: leakAuthToken, AppToken: leakAppToken, RefreshToken: leakRotated}) {
		t.Errorf("tokens after renewing = %+v", got)
	}

	// A rejected app token is renewed, and the request retried
	var rejected atomic.Bool
	api := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/create_certificate") && rejected.CompareAndSwap(false, true) {
			return httpResponse(r, http.StatusUnauthorized, `{"error":"token revoked"}`), nil
		}
		return api.RoundTrip(r)
	})
	if _, err := testSession().RequestCertificate(fakeSA5, publicKey); err != nil || !rejected.Load() {
		t.Errorf("err = %v, rejected = %v", err, rejected.Load())
	}
}

func TestSessionLoginRequired(t *testing.T) {
	fakeVanMoof(t)
	failRequests(t, http.StatusUnauthorized, "/v8/getApplicationToken", "/bikes/")
	_, publicKey, _ := GenerateED25519()
	s := Resume(Tokens{AuthToken: leakAuthToken, AppToken: leakAppToken}) // no refresh token
	if _, err := s.RequestCertificate(fakeSA5, publicKey); !errors.Is(err, ErrLoginRequired) {
		t.Errorf("err = %v, want ErrLoginRequired", err)
	}

	failRequests(t, http.StatusUnauthorized, "/v8/authenticate")
	if _, err := Login(leakEmail, "wrong"); !isUnauthorized(err) {
		t.Errorf("Login with a wrong password: err = %v", err)
	}
}

// Tokens that another call renewed meanwhile are used as they are, without renewing them
// again. Without an app token for the refreshed auth token, there's no session.
func TestSessionRenew(t *testing.T) {
	fakeVanMoof(t)
	requests := countRequests(t)
	s := testSession()
	if tokens, err := s.renew(Tokens{AuthToken: leakAuthToken, AppToken: expiredJWT(), RefreshToken: leakRefresh}, false); err != nil || tokens != s.Tokens() {
		t.Errorf("renew = %+v, %v; want the session's tokens", tokens, err)
	}
	if got := requests(); len(got) != 0 {
		t.Errorf("requests %v, want none", got)
	}

	failRequests(t, http.StatusInternalServerError, "/v8/getApplicationToken")
	s = Resume(Tokens{AuthToken: expiredJWT(), AppToken: expiredJWT(), RefreshToken: leakRefresh})
	if _, err := s.UserID(); !errors.Is(err, ErrLoginRequired) {
		t.Errorf("UserID: err = %v, want ErrLoginRequired", err)
	}
	if s, err := Login(leakEmail, leakPassword); s != nil || err == nil {
		t.Errorf("Login = %v, %v; want an error", s, err)
	}
}

// Goroutines can share a session; finding its app token expired, it renews it once
func TestSessionConcurrentUse(t *testing.T) {
	fakeVanMoof(t)
	var appTokens atomic.Int32
	api := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v8/getApplicationToken" {
			appTokens.Add(1)
		}
		return api.RoundTrip(r)
	})
	_, publicKey, _ := GenerateED25519()
	s := Resume(Tokens{AuthToken: leakAuthToken, AppToken: expiredJWT(), RefreshToken: leakRefresh})

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, err := s.RequestCertificate(fakeSA5, publicKey)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if n := appTokens.Load(); n != 1 {
		t.Errorf("app token renewed %d times, want once", n)
	}
}

// RequestCertificate returns the certificate in VanMoof's answer, or else why there's none
func TestRequestCertificateResponses(t *testing.T) {
	_, publicKey, _ := GenerateED25519()
	tests := []struct {
		body, want string
		err        string // part of the error, or "" for none
	}{
		{`{"certificate":"Q0VSVA=="}`, "Q0VSVA==", ""},
		{`{"err":"Bike not found"}`, "", "no certificate: \"Bike not found\""},
		{`{"err":{"code":404}}`, "", `no certificate: {"code":404}`},
		{`{"certificate":""}`, "", "missing 'certificate'"},
		{`{}`, "", "missing 'certificate'"},
		{`not JSON`, "", "failed to parse"},
	}
	for _, tt := range tests {
		api := http.DefaultTransport
		http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return httpResponse(r, http.StatusOK, tt.body), nil
		})
		cert, err := testSession().RequestCertificate(fakeSA5, publicKey)
		http.DefaultTransport = api
		if cert != tt.want || (err == nil) != (tt.err == "") || (err != nil && !strings.Contains(err.Error(), tt.err)) {
			t.Errorf("%s: RequestCertificate = %q, %v; want %q, %q", tt.body, cert, err, tt.want, tt.err)
		}
	}
}
