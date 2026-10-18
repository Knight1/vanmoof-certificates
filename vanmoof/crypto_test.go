package vanmoof

import (
	"crypto/rand"
	"net/http"
	"testing"
)

// Without randomness there's no key pair, and no certificate is requested for none
func TestGenerateKeyFails(t *testing.T) {
	respondWith(t, func(r *http.Request) (*http.Response, error) {
		t.Errorf("request to %s", r.URL)
		return httpResponse(r, http.StatusInternalServerError, ""), nil
	})
	random := rand.Reader
	rand.Reader = broken{}
	defer func() { rand.Reader = random }()

	if _, _, err := GenerateED25519(); err == nil {
		t.Error("GenerateED25519: no error")
	}
	var account savedAccount
	if _, _, err := account.keyPair(false); err == nil || account.Key != nil {
		t.Errorf("keyPair: err = %v, key pair %+v", err, account.Key)
	}
	var err error
	out := captureStdout(t, func() {
		err = requestCertificates([]Bike{fakeSA5}, leakUUID, testSession(), &account, Options{BikeFilter: "all"})
	})
	if err == nil {
		t.Errorf("requestCertificates: no error\n%s", out)
	}
}
