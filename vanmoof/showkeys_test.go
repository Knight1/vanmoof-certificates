package vanmoof

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// Failing to pick bikes (here: no answer to -bikes ask) is an error, not just a message
func TestShowKeysReportsSelectionError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	fakeVanMoof(t)
	setStdin(t, "")

	var err error
	captureStdout(t, func() { err = ShowKeys(leakEmail, ShowKeysStatic, Options{BikeFilter: "ask", NoCache: true}) })
	if err == nil || !strings.Contains(err.Error(), "failed to select bikes") {
		t.Errorf("err = %v, want failed to select bikes", err)
	}
}

// Both -bikes ask prompts of -show-keys all can be answered from piped input
func TestShowKeysAllAskWithPipedInput(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	fakeVanMoof(t)
	setStdin(t, "1\n1\n")

	var err error
	out := captureStdout(t, func() { err = ShowKeys(leakEmail, ShowKeysAll, Options{BikeFilter: "ask", NoCache: true}) })
	if err != nil || !strings.Contains(out, "bleSecret: ") || !strings.Contains(out, "Certificate valid: ") {
		t.Errorf("err = %v, output:\n%s", err, out)
	}
}

// A failed optional lookup is shown even without -debug, and the rest still works
func TestShowKeysWarnsAboutFailedLookups(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	fakeVanMoof(t)
	api := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		for _, p := range []string{"/v8/getBikeSharingInvitations", "/external/riders/", "/v8/getBikeMessages/"} {
			if strings.HasPrefix(r.URL.Path, p) {
				return &http.Response{StatusCode: http.StatusInternalServerError, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"error":"down"}`)), Request: r}, nil
			}
		}
		return api.RoundTrip(r)
	})

	var err error
	out := captureStdout(t, func() { err = ShowKeys(leakEmail, ShowKeysAll, Options{BikeFilter: "all", NoCache: true}) })
	for _, want := range []string{
		"WARNING: Couldn't check for pending bike sharing invitations: HTTP 500",
		"bikeMessage: couldn't check (HTTP 500",
		"WARNING: Couldn't look up the bikes shared with you: HTTP 500",
		"Certificate valid: " + leakSA5Frame,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if err != nil {
		t.Errorf("err = %v, but the owned bike's certificate worked", err)
	}
}

func detail(id int, profile, key string) BikeDetail {
	d := BikeDetail{BikeID: id, BleProfile: profile}
	d.Key.EncryptionKey = key
	return d
}

func TestFilterKeyBikes(t *testing.T) {
	details := []BikeDetail{
		detail(1, "ELECTRIFIED_2021", "00112233445566778899aabbccddeeff"),
		detail(2, "ELECTRIFIED_2021", ""), // no key yet, still a candidate (for the getBikeMessages check)
		detail(3, "ELECTRIFIED_2023_TRACK_1", "ffeeddccbbaa99887766554433221100"),
		detail(4, "ELECTRIFIED_2022", "00112233445566778899aabbccddeeff"), // cert-only (SA5), excluded
		detail(5, "ELECTRIFIED_2025", ""),                                 // cert-only (S6), excluded
	}

	got := filterKeyBikes(details)
	if len(got) != 3 || got[0].BikeID != 1 || got[1].BikeID != 2 || got[2].BikeID != 3 {
		t.Errorf("filterKeyBikes: got %+v, want bikes 1, 2 and 3", got)
	}
}

func TestIsCertOnlyProfile(t *testing.T) {
	certProfiles := []string{"ELECTRIFIED_2022", "ELECTRIFIED_2025"}
	for _, p := range certProfiles {
		if !isCertOnlyProfile(p) {
			t.Errorf("isCertOnlyProfile(%q) = false, want true", p)
		}
	}

	// Every pre-S5 generation is a static-key bike, not just the handful of profiles
	// seen so far: isCertOnlyProfile must only ever exclude S5/A5 and S6.
	staticProfiles := []string{"ELECTRIFIED_2016", "ELECTRIFIED_2017", "ELECTRIFIED_2018", "ELECTRIFIED_2019", "ELECTRIFIED_2020", "ELECTRIFIED_2021", "ELECTRIFIED_2023_TRACK_1", "SMARTBIKE_2016", "SMARTBIKE_2018", ""}
	for _, p := range staticProfiles {
		if isCertOnlyProfile(p) {
			t.Errorf("isCertOnlyProfile(%q) = true, want false", p)
		}
	}
}
