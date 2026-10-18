package vanmoof

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
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
