package vanmoof

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
)

// apiHeaders builds common VanMoof API headers with the Api-Key included.
func apiHeaders(extra map[string]string) map[string]string {
	headers := map[string]string{
		"Api-Key": apiKey,
	}
	for k, v := range extra {
		headers[k] = v
	}
	return headers
}

func authenticate(email, password string, debug bool) (string, string, error) {
	basicAuth := base64.StdEncoding.EncodeToString([]byte(email + ":" + password))
	headers := apiHeaders(map[string]string{
		"Authorization": "Basic " + basicAuth,
	})

	body, err := doHTTPRequest("POST", apiBaseURL+"/authenticate", nil, headers, debug)
	if err != nil {
		return "", "", err
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", "", err
	}
	if authResp.Token == "" {
		return "", "", errors.New("authentication returned empty token")
	}

	return authResp.Token, authResp.RefreshToken, nil
}

// refreshAuthToken exchanges the refresh token for a new auth token. It also returns the
// refresh token from the response, if any, since the server may rotate it.
func refreshAuthToken(refreshToken string, debug bool) (string, string, error) {
	reqBody, err := json.Marshal(RefreshTokenRequest{RefreshToken: refreshToken})
	if err != nil {
		return "", "", err
	}

	headers := apiHeaders(map[string]string{
		"Content-Type": "application/json",
	})

	body, err := doHTTPRequest("POST", apiBaseURL+"/token", bytes.NewBuffer(reqBody), headers, debug)
	if err != nil {
		return "", "", err
	}

	var resp AuthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", "", err
	}
	if resp.Token == "" {
		return "", "", errors.New("token refresh returned empty token")
	}

	return resp.Token, resp.RefreshToken, nil
}

func getApplicationToken(authToken string, debug bool) (string, error) {
	headers := apiHeaders(map[string]string{
		"Authorization": "Bearer " + authToken,
	})

	body, err := doHTTPRequest("GET", apiBaseURL+"/getApplicationToken", nil, headers, debug)
	if err != nil {
		return "", err
	}

	var appTokenResp AppTokenResponse
	if err := json.Unmarshal(body, &appTokenResp); err != nil {
		return "", err
	}
	if appTokenResp.Token == "" {
		return "", errors.New("application token request returned empty token")
	}

	// Validate and decode JWT in debug mode
	if debug {
		validateAndShowJWT(appTokenResp.Token)
	}

	return appTokenResp.Token, nil
}

// getSharedVehicles uses the Vehicle Registry API which does not require the Api-Key header.
func getSharedVehicles(riderUUID, appToken string, debug bool) ([]VehicleAccess, error) {
	headers := map[string]string{
		"Authorization": "Bearer " + appToken,
	}

	endpoint := fmt.Sprintf(vehicleRegistryBaseURL+"/external/riders/%s/vehicles", url.PathEscape(riderUUID))
	body, err := doHTTPRequest("GET", endpoint, nil, headers, debug)
	if err != nil {
		return nil, err
	}

	var resp RiderVehiclesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return resp.VehicleAccess, nil
}

func getBikeSharingInvitations(authToken string, debug bool) (int, error) {
	headers := apiHeaders(map[string]string{
		"Authorization": "Bearer " + authToken,
	})

	body, err := doHTTPRequest("GET", apiBaseURL+"/getBikeSharingInvitations", nil, headers, debug)
	if err != nil {
		return 0, err
	}

	var resp BikeSharingInvitationsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, err
	}

	return len(resp.Invitations), nil
}

// getBikeMessages checks for messages queued for BLE delivery to a bike (getBikeMessages
// returns [] when nothing is waiting, or a list of {"content": "..."} entries otherwise).
func getBikeMessages(bikeID int, authToken string, debug bool) ([]BikeMessage, error) {
	headers := apiHeaders(map[string]string{
		"Authorization": "Bearer " + authToken,
	})

	body, err := doHTTPRequest("GET", fmt.Sprintf(apiBaseURL+"/getBikeMessages/%d", bikeID), nil, headers, debug)
	if err != nil {
		return nil, err
	}

	var messages []BikeMessage
	if err := json.Unmarshal(body, &messages); err != nil {
		return nil, err
	}

	return messages, nil
}

func fetchCustomerData(authToken string, debug bool) (*CustomerData, error) {
	headers := apiHeaders(map[string]string{
		"Authorization": "Bearer " + authToken,
	})

	body, err := doHTTPRequest("GET", apiBaseURL+"/getCustomerData?includeBikeDetails", nil, headers, debug)
	if err != nil {
		return nil, err
	}

	var customerData CustomerData
	if err := json.Unmarshal(body, &customerData); err != nil {
		return nil, err
	}

	return &customerData, nil
}
