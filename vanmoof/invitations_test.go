package vanmoof

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestSessionInvitations(t *testing.T) {
	fakeVanMoof(t)
	s := testSession()

	invitations, err := s.Invitations()
	if err != nil || len(invitations) != 1 {
		t.Fatalf("Invitations() = %+v, %v", invitations, err)
	}
	inv := invitations[0]
	if inv.GUID != leakInviteGUID || inv.OwnerName != leakOwnerName || inv.BikeName != leakInvitedName || inv.Model() != "S5" || inv.ExpiresAt == "" {
		t.Errorf("invitation %+v", inv)
	}

	bike, err := s.AcceptInvitation(inv.GUID)
	if err != nil || bike.FrameNumber != leakInvitedFrame || bike.BikeID != leakInvitedID || bike.Owner != leakOwnerName || !bike.UsesCertificates() {
		t.Errorf("AcceptInvitation = %+v, %v", bike, err)
	}
	if err := s.DeclineInvitation(inv.GUID); err != nil {
		t.Errorf("DeclineInvitation: %v", err)
	}
	if err := s.DeclineInvitation("1eaf0000-0000-3000-8000-0000000000dd"); err == nil {
		t.Error("declining an invitation that doesn't exist: no error")
	}
	if _, err := s.AcceptInvitation(""); err == nil {
		t.Error("accepting no invitation: no error")
	}
	if err := s.DeclineInvitation(""); err == nil {
		t.Error("declining no invitation: no error")
	}
}

// -invitations reports an answer that fails, and a list it can't get
func TestInvitationsFail(t *testing.T) {
	useTempCache(t, "")
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	fakeVanMoof(t)
	failRequests(t, http.StatusInternalServerError, "/v8/declineBikeSharingInvitation/")
	var err error
	out := captureStdout(t, func() { err = Invitations(leakEmail, InvitationsDecline, "1", Options{}) })
	if err == nil || err.Error() != "1 of 1 invitation(s) failed" || !strings.Contains(out, "Failed to decline the invitation for "+leakInvitedName+": HTTP 500") {
		t.Errorf("err = %v\n%s", err, out)
	}

	failRequests(t, http.StatusInternalServerError, "/v8/getBikeSharingInvitations")
	captureStdout(t, func() { err = Invitations(leakEmail, InvitationsList, "", Options{}) })
	if err == nil || !strings.Contains(err.Error(), "failed to get the bike sharing invitations: HTTP 500") {
		t.Errorf("err = %v", err)
	}
}

// -invitations lists the invitations, and accepts or declines the ones given, or asked for
func TestInvitations(t *testing.T) {
	useTempCache(t, "")
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	fakeVanMoof(t)
	var posted []string // the accept and decline requests
	api := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "BikeSharingInvitation/") {
			posted = append(posted, strings.TrimPrefix(r.URL.Path, "/v8/"))
		}
		return api.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = api })

	run := func(action, selection string) (string, error) {
		t.Helper()
		var err error
		out := captureStdout(t, func() { err = Invitations(leakEmail, action, selection, Options{}) })
		return out, err
	}

	out, err := run(InvitationsList, "")
	for _, want := range []string{"Invitation 1\n", "Bike: " + leakInvitedName, "Model: S5 (Find My)", "Owner: " + leakOwnerName, "GUID: " + leakInviteGUID} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	if err != nil || len(posted) != 0 {
		t.Errorf("list: %v, posted %q", err, posted)
	}

	accept, decline := "acceptBikeSharingInvitation/"+leakInviteGUID, "declineBikeSharingInvitation/"+leakInviteGUID
	tests := []struct {
		name, action, selection string
		stdin                   string   // answer to the question which
		posted                  []string // requests made
		err                     bool
	}{
		{"accept by number", InvitationsAccept, "1", "", []string{accept}, false},
		{"decline by GUID", InvitationsDecline, strings.ToUpper(leakInviteGUID), "", []string{decline}, false},
		{"accept all", InvitationsAccept, "all", "", []string{accept}, false},
		{"given twice", InvitationsAccept, "1," + leakInviteGUID, "", []string{accept}, false},
		{"asked which", InvitationsDecline, "", "1\n", []string{decline}, false},
		{"asked, none", InvitationsAccept, "", "\n", nil, false},
		{"no such invitation", InvitationsAccept, "2", "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			posted = nil
			setStdin(t, tt.stdin)
			out, err := run(tt.action, tt.selection)
			if (err != nil) != tt.err || !slices.Equal(posted, tt.posted) {
				t.Errorf("err = %v, posted %q, want %q\n%s", err, posted, tt.posted, out)
			}
		})
	}

	// A failure is reported, in the exit status too
	failRequests(t, http.StatusNotFound, "/v8/acceptBikeSharingInvitation/")
	if out, err := run(InvitationsAccept, "1"); err == nil || !strings.Contains(out, "Failed to accept the invitation") {
		t.Errorf("failed accept: err = %v\n%s", err, out)
	}

	// The certificate flows point to -invitations
	if out := captureStdout(t, func() { warnPendingInvitations(leakAuthToken, false) }); !strings.Contains(out, "-invitations accept") {
		t.Errorf("warning: %q", out)
	}
}

func TestNoInvitations(t *testing.T) {
	useTempCache(t, "")
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	fakeVanMoof(t)
	api := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v8/getBikeSharingInvitations" {
			return httpResponse(r, http.StatusOK, `{"invitations":[],"hash":"x"}`), nil
		}
		return api.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = api })

	var err error
	out := captureStdout(t, func() { err = Invitations(leakEmail, InvitationsAccept, "all", Options{}) })
	if err != nil || !strings.Contains(out, "No pending bike sharing invitations") {
		t.Errorf("err = %v\n%s", err, out)
	}
}

func TestSelectInvitations(t *testing.T) {
	a, b, c := Invitation{GUID: "aaaa-1"}, Invitation{GUID: "bbbb-2"}, Invitation{GUID: "cccc-3"}
	invitations := []Invitation{a, b, c}
	tests := []struct {
		selection, stdin string
		want             []Invitation
		err              bool
	}{
		{"2", "", []Invitation{b}, false},
		{"3, 1", "", []Invitation{c, a}, false},
		{"all", "", invitations, false},
		{"BBBB-2", "", []Invitation{b}, false},
		{"1,aaaa-1,1", "", []Invitation{a}, false},
		{"", "2\n", []Invitation{b}, false}, // asked
		{"", "all\n", invitations, false},
		{"", "\n", nil, false},
		{"0", "", nil, true},
		{"4", "", nil, true},
		{"dddd-4", "", nil, true},
	}
	for _, tt := range tests {
		setStdin(t, tt.stdin)
		var got []Invitation
		var err error
		captureStdout(t, func() { got, err = selectInvitations(invitations, InvitationsAccept, tt.selection) })
		if (err != nil) != tt.err || !slices.Equal(got, tt.want) {
			t.Errorf("selection %q (stdin %q) = %v, %v; want %v", tt.selection, tt.stdin, got, err, tt.want)
		}
	}
}

// A decline that VanMoof doesn't confirm is an error
func TestDeclineNotConfirmed(t *testing.T) {
	fakeVanMoof(t)
	api := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasPrefix(r.URL.Path, "/v8/declineBikeSharingInvitation/") {
			return httpResponse(r, http.StatusOK, `{"result":false}`), nil
		}
		return api.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = api })
	if err := testSession().DeclineInvitation(leakInviteGUID); err == nil {
		t.Error("no error")
	}
}

// An invitation names the model of the bike's frame shape, with whether it works with
// Find My if that's known, or the model name VanMoof gives without a BLE profile
func TestPrintInvitationModel(t *testing.T) {
	out := captureStdout(t, func() {
		printInvitations([]Invitation{{BleProfile: "ELECTRIFIED_2021", FrameShape: "X"}, {BleProfile: "ELECTRIFIED_2022"}, {ModelName: "B-05S-E01EU-XX"}})
	})
	for _, want := range []string{"Model: X3 (Find My)\n", "Model: SA5 (Find My)\n", "Model: B-05S-E01EU-XX\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}
