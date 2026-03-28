package vanmoof

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	return authResp.Token, authResp.RefreshToken, nil
}

func refreshAuthToken(refreshToken string, debug bool) (string, error) {
	reqBody, err := json.Marshal(RefreshTokenRequest{RefreshToken: refreshToken})
	if err != nil {
		return "", err
	}

	headers := apiHeaders(map[string]string{
		"Content-Type": "application/json",
	})

	body, err := doHTTPRequest("POST", apiBaseURL+"/token", bytes.NewBuffer(reqBody), headers, debug)
	if err != nil {
		return "", err
	}

	var resp AuthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}

	return resp.Token, nil
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

	url := fmt.Sprintf(vehicleRegistryBaseURL+"/external/riders/%s/vehicles", riderUUID)
	body, err := doHTTPRequest("GET", url, nil, headers, debug)
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

func getCustomerData(authToken string, debug bool) (string, []BikeData, error) {
	headers := apiHeaders(map[string]string{
		"Authorization": "Bearer " + authToken,
	})

	body, err := doHTTPRequest("GET", apiBaseURL+"/getCustomerData?includeBikeDetails", nil, headers, debug)
	if err != nil {
		return "", nil, err
	}

	var customerData CustomerData
	if err := json.Unmarshal(body, &customerData); err != nil {
		return "", nil, err
	}

	return customerData.Data.UUID, customerData.Data.Bikes, nil
}
