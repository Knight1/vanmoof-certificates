package main

import (
	"encoding/base64"
	"encoding/json"
)

func authenticate(email, password string, debug bool) (string, error) {
	basicAuth := base64.StdEncoding.EncodeToString([]byte(email + ":" + password))
	headers := map[string]string{
		"Authorization": "Basic " + basicAuth,
		"Api-Key":       ApiKey,
		"User-Agent":    UserAgent,
	}

	body, err := doHTTPRequest("POST", ApiBaseURL+"/authenticate", nil, headers, debug)
	if err != nil {
		return "", err
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", err
	}

	return authResp.Token, nil
}

func getApplicationToken(authToken string, debug bool) (string, error) {
	headers := map[string]string{
		"Authorization": "Bearer " + authToken,
		"Api-Key":       ApiKey,
		"User-Agent":    UserAgent,
	}

	body, err := doHTTPRequest("GET", ApiBaseURL+"/getApplicationToken", nil, headers, debug)
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

func getCustomerData(authToken string, debug bool) (string, []BikeData, error) {
	headers := map[string]string{
		"Authorization": "Bearer " + authToken,
		"Api-Key":       ApiKey,
		"User-Agent":    UserAgent,
	}

	body, err := doHTTPRequest("GET", ApiBaseURL+"/getCustomerData?includeBikeDetails", nil, headers, debug)
	if err != nil {
		return "", nil, err
	}

	var customerData CustomerData
	if err := json.Unmarshal(body, &customerData); err != nil {
		return "", nil, err
	}

	return customerData.Data.UUID, customerData.Data.Bikes, nil
}
