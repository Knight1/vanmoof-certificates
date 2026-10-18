package vanmoof

import (
	"errors"
	"net/http"
	"testing"
)

// A redirect is an error, and isn't followed: that would send the request's token to
// wherever it points
func TestRedirectIsAnError(t *testing.T) {
	var requests []string
	api := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.URL.String())
		resp := httpResponse(r, http.StatusFound, `{"token":"from the redirect"}`)
		resp.Header.Set("Location", "https://example.com/elsewhere")
		return resp, nil
	})
	t.Cleanup(func() { http.DefaultTransport = api })

	token, err := getApplicationToken(leakAuthToken, false)
	var httpErr *httpError
	if !errors.As(err, &httpErr) || httpErr.statusCode != http.StatusFound {
		t.Errorf("getApplicationToken = %q, %v; want an HTTP 302 error", token, err)
	}
	if len(requests) != 1 {
		t.Errorf("requests %q, want only the first one", requests)
	}
}
