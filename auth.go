package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func authenticate(email, password string, debug bool) (string, error) {
	basicAuth := base64.StdEncoding.EncodeToString([]byte(email + ":" + password))
	headers := map[string]string{
		"Authorization": "Basic " + basicAuth,
		"Api-Key":       ApiKey,
		"User-Agent":    UserAgent,
	}

	body, err := doHTTPRequest("POST", "https://api.vanmoof-api.com/v8/authenticate", nil, headers, debug)
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

	// Validate and decode JWT in debug mode
	if debug {
		validateAndShowJWT(appTokenResp.Token)
	}

	return appTokenResp.Token, nil
}

func validateAndShowJWT(tokenString string) {
	fmt.Println("\n[DEBUG] JWT Token Analysis:")

	// Parse without validation first to inspect the token
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})

	if err != nil {
		fmt.Printf("[DEBUG] Failed to parse JWT: %v\n", err)
		return
	}

	// Show header
	if headerJSON, err := json.MarshalIndent(token.Header, "[DEBUG]   ", "  "); err == nil {
		fmt.Printf("[DEBUG] JWT Header:\n%s\n", string(headerJSON))
	}

	// Show claims/payload
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if claimsJSON, err := json.MarshalIndent(claims, "[DEBUG]   ", "  "); err == nil {
			fmt.Printf("[DEBUG] JWT Payload:\n%s\n", string(claimsJSON))
		}
	}

	// Show signature info
	parts := strings.Split(tokenString, ".")
	if len(parts) == 3 {
		fmt.Printf("[DEBUG] JWT Signature (base64): %s...\n", parts[2][:min(40, len(parts[2]))])
	}

	fmt.Println()
}

func getCustomerData(authToken string, debug bool) (string, []BikeData, error) {
	headers := map[string]string{
		"Authorization": "Bearer " + authToken,
		"Api-Key":       ApiKey,
		"User-Agent":    UserAgent,
	}

	body, err := doHTTPRequest("GET", "https://api.vanmoof-api.com/v8/getCustomerData?includeBikeDetails", nil, headers, debug)
	if err != nil {
		return "", nil, err
	}

	var customerData CustomerData
	if err := json.Unmarshal(body, &customerData); err != nil {
		return "", nil, err
	}

	return customerData.Data.UUID, customerData.Data.Bikes, nil
}
