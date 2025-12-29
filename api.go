package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

func getCert(email, password string, debug bool) error {
	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	privKeyB64 := base64.StdEncoding.EncodeToString(privKey)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	fmt.Printf("Privkey = %s\n", privKeyB64)
	fmt.Printf("Pubkey = %s\n", pubKeyB64)
	fmt.Println()

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

	// Step 4: Process each bike and create certificate
	for _, bike := range bikes {
		fmt.Printf("Bike %s\n", bike.Name)
		fmt.Printf("Bike ID: %d\n", bike.BikeID)
		fmt.Printf("Frame number: %s\n", bike.FrameNumber)
		fmt.Printf("Frame serial: %s\n", bike.FrameSerial)

		if debug {
			fmt.Printf("[DEBUG] BleProfile: %s, MainEcuSerial: %s\n", bike.BleProfile, bike.MainEcuSerial)
		}

		if bike.BleProfile == "ELECTRIFIED_2022" {
			fmt.Println("Bike is an SA5")
			fmt.Printf("ECU Serial: %s\n", bike.MainEcuSerial)

			if debug {
				fmt.Printf("[DEBUG] Creating certificate for bike frame number %s\n", bike.FrameNumber)
			}

			certResp, err := createCertificate(bike.FrameNumber, pubKeyB64, appToken, debug)
			if err != nil {
				fmt.Printf("Failed to create certificate: %v\n", err)
				continue
			}

			fmt.Println("Certificate below:")
			fmt.Println("-----------")
			fmt.Println(certResp)
			fmt.Println("-----------")
		} else {
			fmt.Println("Not an SA5.")
		}
	}

	fmt.Println()
	fmt.Println()

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func authenticate(email, password string, debug bool) (string, error) {
	if debug {
		fmt.Println("[DEBUG] POST https://my.vanmoof.com/api/v8/authenticate")
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://my.vanmoof.com/api/v8/authenticate", nil)
	if err != nil {
		return "", err
	}

	basicAuth := base64.StdEncoding.EncodeToString([]byte(email + ":" + password))
	req.Header.Set("Authorization", "Basic "+basicAuth)
	req.Header.Set("Api-Key", ApiKey)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if debug {
		fmt.Printf("[DEBUG] Response status: %d\n", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if debug {
		fmt.Printf("[DEBUG] Response body: %s\n", string(body))
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", err
	}

	return authResp.Token, nil
}

func getApplicationToken(authToken string, debug bool) (string, error) {
	if debug {
		fmt.Println("[DEBUG] GET https://api.vanmoof-api.com/v8/getApplicationToken")
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://api.vanmoof-api.com/v8/getApplicationToken", nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Api-Key", ApiKey)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if debug {
		fmt.Printf("[DEBUG] Response status: %d\n", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if debug {
		fmt.Printf("[DEBUG] Response body: %s\n", string(body))
	}

	var appTokenResp AppTokenResponse
	if err := json.Unmarshal(body, &appTokenResp); err != nil {
		return "", err
	}

	return appTokenResp.Token, nil
}

func getCustomerData(authToken string, debug bool) ([]BikeData, error) {
	if debug {
		fmt.Println("[DEBUG] GET https://my.vanmoof.com/api/v8/getCustomerData?includeBikeDetails")
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://my.vanmoof.com/api/v8/getCustomerData?includeBikeDetails", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Api-Key", ApiKey)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if debug {
		fmt.Printf("[DEBUG] Response status: %d\n", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if debug {
		fmt.Printf("[DEBUG] Response body length: %d bytes\n", len(body))
	}

	var customerData CustomerData
	if err := json.Unmarshal(body, &customerData); err != nil {
		return nil, err
	}

	return customerData.Data.Bikes, nil
}

func createCertificate(bikeID, pubKey, appToken string, debug bool) (string, error) {
	if debug {
		fmt.Printf("[DEBUG] POST https://bikeapi.production.vanmoof.cloud/bikes/%s/create_certificate\n", bikeID)
	}

	client := &http.Client{}

	certReq := CertificateRequest{
		PublicKey: pubKey,
	}

	reqBody, err := json.Marshal(certReq)
	if err != nil {
		return "", err
	}

	if debug {
		fmt.Printf("[DEBUG] Request body: %s\n", string(reqBody))
	}

	url := fmt.Sprintf("https://bikeapi.production.vanmoof.cloud/bikes/%s/create_certificate", bikeID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+appToken)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if debug {
		fmt.Printf("[DEBUG] Response status: %d\n", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if debug {
		fmt.Printf("[DEBUG] Response body: %s\n", string(body))
	}

	return string(body), nil
}
