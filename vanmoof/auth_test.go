package vanmoof

import (
	"net/http"
	"testing"
)

// An answer that isn't the JSON asked for is an error, whatever the request
func TestBrokenResponses(t *testing.T) {
	respondWith(t, func(r *http.Request) (*http.Response, error) { return httpResponse(r, http.StatusOK, `{"broken`), nil })
	requests := map[string]func() error{
		"authenticate":        func() error { _, _, err := authenticate(leakEmail, leakPassword, false); return err },
		"refreshAuthToken":    func() error { _, _, err := refreshAuthToken(leakRefresh, false); return err },
		"getApplicationToken": func() error { _, err := getApplicationToken(leakAuthToken, false); return err },
		"getSharedVehicles":   func() error { _, err := getSharedVehicles(leakUUID, leakAppToken, false); return err },
		"getBikeSharingInvitations": func() error {
			_, err := getBikeSharingInvitations(leakAuthToken, false)
			return err
		},
		"acceptBikeSharingInvitation": func() error {
			_, err := acceptBikeSharingInvitation(leakInviteGUID, leakAuthToken, false)
			return err
		},
		"declineBikeSharingInvitation": func() error { return declineBikeSharingInvitation(leakInviteGUID, leakAuthToken, false) },
		"getBikeMessages":              func() error { _, err := getBikeMessages(leakS2ID, leakAuthToken, false); return err },
		"fetchCustomerData":            func() error { _, err := fetchCustomerData(leakAuthToken, false); return err },
	}
	for name, request := range requests {
		if err := request(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
