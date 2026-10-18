package vanmoof

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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

// respondWith answers every request with respond, for the duration of the test
func respondWith(t *testing.T, respond func(r *http.Request) (*http.Response, error)) {
	t.Helper()
	api := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(respond)
	t.Cleanup(func() { http.DefaultTransport = api })
}

// Debug output shows the rate limit headers, with the reset time readable
func TestDebugRateLimit(t *testing.T) {
	reset := time.Now().Add(time.Minute).Unix()
	for _, tt := range []struct{ reset, want string }{
		{fmt.Sprint(reset), "[DEBUG] Rate Limit Reset: " + time.Unix(reset, 0).Format("2006-01-02 15:04:05 MST")},
		{"soon\x1b[2J", `[DEBUG] Rate Limit Reset: soon\x1b[2J`},
	} {
		respondWith(t, func(r *http.Request) (*http.Response, error) {
			resp := httpResponse(r, http.StatusOK, `{}`)
			resp.Header.Set("x-ratelimit-limit", "100")
			resp.Header.Set("x-ratelimit-remaining", "99")
			resp.Header.Set("x-ratelimit-reset", tt.reset)
			return resp, nil
		})
		out := captureStdout(t, func() { doHTTPRequest("GET", apiBaseURL+"/getCustomerData", nil, nil, true) })
		for _, want := range []string{"[DEBUG] Rate Limit: 100 requests", "[DEBUG] Rate Limit Remaining: 99 requests", tt.want} {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
		}
	}
}

// A response bigger than 10 MB is an error, instead of being kept in memory
func TestResponseTooLarge(t *testing.T) {
	respondWith(t, func(r *http.Request) (*http.Response, error) {
		return httpResponse(r, http.StatusOK, strings.Repeat("a", 10*1024*1024+1)), nil
	})
	if _, err := doHTTPRequest("GET", apiBaseURL+"/getCustomerData", nil, nil, false); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("err = %v", err)
	}
}

// A request that doesn't get an answer is an error
func TestNoAnswer(t *testing.T) {
	offline := errors.New("no network")
	respondWith(t, func(r *http.Request) (*http.Response, error) { return nil, offline })
	if _, err := doHTTPRequest("GET", apiBaseURL+"/getCustomerData", nil, nil, false); !errors.Is(err, offline) {
		t.Errorf("err = %v", err)
	}
}

// broken fails every read
type broken struct{}

func (broken) Read([]byte) (int, error) { return 0, errors.New("broken") }

// A request that can't be made, or whose answer can't be read, is an error. An error page
// is cut short in the error.
func TestRequestErrors(t *testing.T) {
	if _, err := doHTTPRequest("GET", "https://[not a host", nil, nil, false); err == nil {
		t.Error("no error for a URL that isn't one")
	}

	respondWith(t, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(broken{}), Request: r}, nil
	})
	if _, err := doHTTPRequest("GET", apiBaseURL+"/getCustomerData", nil, nil, false); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Errorf("err = %v for an answer that can't be read", err)
	}

	respondWith(t, func(r *http.Request) (*http.Response, error) {
		return httpResponse(r, http.StatusInternalServerError, strings.Repeat("x", 600)), nil
	})
	if _, err := doHTTPRequest("GET", apiBaseURL+"/getCustomerData", nil, nil, false); err == nil || err.Error() != "HTTP 500: "+strings.Repeat("x", 500)+"... (truncated)" {
		t.Errorf("err = %v for a long error page", err)
	}
}

// An ID in a request URL is one path segment, and an empty one, "." or ".." is refused
func TestPathSegment(t *testing.T) {
	for id, want := range map[string]string{"BBBBBB00001AA": "BBBBBB00001AA", "a/b": "a%2Fb", "a?b#c": "a%3Fb%23c", "%2e%2e": "%252e%252e", "...": "..."} {
		if got, err := pathSegment(id); got != want || err != nil {
			t.Errorf("pathSegment(%q) = %q, %v; want %q", id, got, err, want)
		}
	}
	for _, id := range []string{"", ".", ".."} {
		if _, err := pathSegment(id); err == nil {
			t.Errorf("pathSegment(%q): no error", id)
		}
	}
}
