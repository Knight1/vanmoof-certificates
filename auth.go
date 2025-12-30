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

	body, err := doHTTPRequest("POST", "https://my.vanmoof.com/api/v8/authenticate", nil, headers, debug)
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

	body, err := doHTTPRequest("GET", "https://api.vanmoof-api.com/v8/getApplicationToken", nil, headers, debug)
	if err != nil {
		return "", err
	}

	var appTokenResp AppTokenResponse
	if err := json.Unmarshal(body, &appTokenResp); err != nil {
		return "", err
	}

	return appTokenResp.Token, nil
}

func getCustomerData(authToken string, debug bool) (string, []BikeData, error) {
	headers := map[string]string{
		"Authorization": "Bearer " + authToken,
		"Api-Key":       ApiKey,
		"User-Agent":    UserAgent,
	}

	body, err := doHTTPRequest("GET", "https://my.vanmoof.com/api/v8/getCustomerData?includeBikeDetails", nil, headers, debug)
	if err != nil {
		return "", nil, err
	}

	var customerData CustomerData
	if err := json.Unmarshal(body, &customerData); err != nil {
		return "", nil, err
	}

	return customerData.Data.UUID, customerData.Data.Bikes, nil
}
