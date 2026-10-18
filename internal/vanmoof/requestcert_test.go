package vanmoof

import (
	"encoding/base64"
	"encoding/json"
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

	good := BikeData{BikeID: 1, FrameNumber: "BBBBBB00001AA", BleProfile: "ELECTRIFIED_2022"}
	refused := BikeData{BikeID: 2, FrameNumber: "BBBBBB00002AA", BleProfile: "ELECTRIFIED_2022"}
	wrong := BikeData{BikeID: 3, FrameNumber: "BBBBBB00003AA", BleProfile: "ELECTRIFIED_2022"}

	var err error
	out := captureStdout(t, func() { err = requestCertificates([]BikeData{refused, wrong, good}, "", "app", "all", "", false) })
	if err == nil || err.Error() != "2 of 3 certificate(s) failed" {
		t.Errorf("err = %v, want 2 of 3 certificate(s) failed", err)
	}
	if !strings.Contains(out, "Certificate valid: BBBBBB00001AA") {
		t.Errorf("the valid certificate wasn't processed after the failed ones:\n%s", out)
	}

	captureStdout(t, func() { err = requestCertificates([]BikeData{good}, "", "app", "all", "", false) })
	if err != nil {
		t.Errorf("err = %v for a valid certificate", err)
	}
}
