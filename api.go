package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	ApiKey    = "fcb38d47-f14b-30cf-843b-26283f6a5819"
	UserAgent = "VanMoof/20 CFNetwork/1404.0.5 Darwin/22.3.0"
)

type AuthResponse struct {
	Token string `json:"token"`
}

type AppTokenResponse struct {
	Token string `json:"token"`
}

type BikeData struct {
	Name          string `json:"name"`
	BikeID        int    `json:"id"`
	FrameNumber   string `json:"frameNumber"`
	FrameSerial   string `json:"frameSerial"`
	BleProfile    string `json:"bleProfile"`
	MainEcuSerial string `json:"mainEcuSerial"`
}

type CustomerData struct {
	Data struct {
		Bikes []BikeData `json:"bikes"`
	} `json:"data"`
}

type CertificateRequest struct {
	PublicKey string `json:"public_key"`
}

type CertificateResponse struct {
	Certificate string `json:"certificate"`
}

func getCert(email, password, bikeFilter string, debug bool) error {
	if debug {
		fmt.Println("[DEBUG] Starting authentication...")
	}

	// Step 1: Authenticate
	authToken, err := authenticate(email, password, debug)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	if debug {
		fmt.Printf("[DEBUG] Auth token received: %s...\n", authToken[:min(20, len(authToken))])
	}

	// Step 2: Get application token
	appToken, err := getApplicationToken(authToken, debug)
	if err != nil {
		return fmt.Errorf("failed to get app token: %w", err)
	}

	if debug {
		fmt.Printf("[DEBUG] App token received: %s...\n", appToken[:min(20, len(appToken))])
	}

	// Step 3: Get customer data (bikes)
	bikes, err := getCustomerData(authToken, debug)
	if err != nil {
		return fmt.Errorf("failed to get customer data: %w", err)
	}

	if debug {
		fmt.Printf("[DEBUG] Retrieved %d bikes\n", len(bikes))
	}

	// Filter for SA5 bikes only
	var sa5Bikes []BikeData
	for _, bike := range bikes {
		if bike.BleProfile == "ELECTRIFIED_2022" {
			sa5Bikes = append(sa5Bikes, bike)
		}
	}

	if len(sa5Bikes) == 0 {
		fmt.Println("No SA5 bikes found")
		return nil
	}

	// Filter bikes based on user selection
	selectedBikes, err := selectBikes(sa5Bikes, bikeFilter)
	if err != nil {
		return err
	}

	if len(selectedBikes) == 0 {
		fmt.Println("No bikes selected")
		return nil
	}

	// Generate Ed25519 key pair only when SA5 bikes are found
	privKeyB64, pubKeyB64, err := generateED25519()
	if err != nil {
		return err
	}

	fmt.Printf("Privkey = %s\n", privKeyB64)
	fmt.Printf("Pubkey = %s\n", pubKeyB64)
	fmt.Println()

	// Step 4: Process each selected SA5 bike and create certificate
	for _, bike := range selectedBikes {
		fmt.Printf("Bike ID: %d\n", bike.BikeID)
		fmt.Printf("Frame number: %s\n", bike.FrameNumber)
		fmt.Println("Bike is an SA5")

		if debug {
			fmt.Printf("[DEBUG] Creating certificate for bike ID %d\n", bike.BikeID)
		}

		certResp, err := createCertificate(bike.FrameNumber, pubKeyB64, appToken, debug)
		if err != nil {
			fmt.Printf("Failed to create certificate: %v\n", err)
			continue
		}

		// Check if response contains an error
		var respData map[string]interface{}
		if err := json.Unmarshal([]byte(certResp), &respData); err == nil {
			if _, hasErr := respData["err"]; hasErr {
				fmt.Printf("Certificate error: %v\n", certResp)
				continue
			}
		}

		fmt.Println("Certificate:")
		fmt.Println(certResp)

		// Parse the certificate
		if cert, ok := respData["certificate"].(string); ok {
			fmt.Println("Parsing certificate...")
			processCertificate(cert, pubKeyB64, fmt.Sprintf("%d", bike.BikeID), debug)
		}
	}
	return nil
}

func generateED25519() (string, string, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key pair: %w", err)
	}

	privKeyB64 := base64.StdEncoding.EncodeToString(privKey)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	return privKeyB64, pubKeyB64, nil
}

func selectBikes(bikes []BikeData, filter string) ([]BikeData, error) {
	if filter == "all" {
		return bikes, nil
	}

	if filter == "ask" {
		// Display available bikes
		fmt.Println("\nAvailable SA5 bikes:")
		for i, bike := range bikes {
			fmt.Printf("%d. Bike ID: %d, Frame: %s\n", i+1, bike.BikeID, bike.FrameNumber)
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("\nEnter bike numbers to process (comma-separated, or 'all'): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read input: %w", err)
		}
		filter = strings.TrimSpace(input)

		if filter == "all" {
			return bikes, nil
		}
	}

	// Parse comma-separated bike IDs or indices
	var selected []BikeData
	parts := strings.Split(filter, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Try to parse as index (1-based)
		var idx int
		if _, err := fmt.Sscanf(part, "%d", &idx); err == nil {
			if idx > 0 && idx <= len(bikes) {
				selected = append(selected, bikes[idx-1])
				continue
			}
		}

		// Try to parse as bike ID
		var bikeID int
		if _, err := fmt.Sscanf(part, "%d", &bikeID); err == nil {
			for _, bike := range bikes {
				if bike.BikeID == bikeID {
					selected = append(selected, bike)
					break
				}
			}
		}
	}

	return selected, nil
}

func doHTTPRequest(method, url string, body io.Reader, headers map[string]string, debug bool) ([]byte, error) {
	if debug {
		fmt.Printf("[DEBUG] %s %s\n", method, url)
		if body != nil {
			if buf, ok := body.(*bytes.Buffer); ok {
				fmt.Printf("[DEBUG] Request body: %s\n", buf.String())
			}
		}
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if debug {
		fmt.Printf("[DEBUG] Response status: %d\n", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if debug {
		if len(respBody) > 200 {
			fmt.Printf("[DEBUG] Response body length: %d bytes\n", len(respBody))
		} else {
			fmt.Printf("[DEBUG] Response body: %s\n", string(respBody))
		}
	}

	// Check for HTTP errors
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

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

func getCustomerData(authToken string, debug bool) ([]BikeData, error) {
	headers := map[string]string{
		"Authorization": "Bearer " + authToken,
		"Api-Key":       ApiKey,
		"User-Agent":    UserAgent,
	}

	body, err := doHTTPRequest("GET", "https://my.vanmoof.com/api/v8/getCustomerData?includeBikeDetails", nil, headers, debug)
	if err != nil {
		return nil, err
	}

	var customerData CustomerData
	if err := json.Unmarshal(body, &customerData); err != nil {
		return nil, err
	}

	return customerData.Data.Bikes, nil
}

func createCertificate(bikeID, pubKey, appToken string, debug bool) (string, error) {
	certReq := CertificateRequest{
		PublicKey: pubKey,
	}

	reqBody, err := json.Marshal(certReq)
	if err != nil {
		return "", err
	}

	headers := map[string]string{
		"Authorization": "Bearer " + appToken,
		"User-Agent":    UserAgent,
		"Content-Type":  "application/json",
	}

	url := fmt.Sprintf("https://bikeapi.production.vanmoof.cloud/bikes/%s/create_certificate", bikeID)
	body, err := doHTTPRequest("POST", url, bytes.NewBuffer(reqBody), headers, debug)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
