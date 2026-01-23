package main

import (
	"encoding/json"
	"fmt"
)

func getCert(email, password, bikeFilter, pubkey string, debug bool) error {
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
	customerUUID, bikes, err := getCustomerData(authToken, debug)
	if err != nil {
		return fmt.Errorf("failed to get customer data: %w", err)
	}

	if debug {
		fmt.Printf("[DEBUG] Customer UUID: %s\n", customerUUID)
	}

	if debug {
		fmt.Printf("[DEBUG] Retrieved %d bikes\n", len(bikes))
	}

	// Filter for SA5 bikes only
	var sa5Bikes []BikeData
	for _, bike := range bikes {
		for _, profile := range SupportedBleProfiles {
			if bike.BleProfile == profile {
				sa5Bikes = append(sa5Bikes, bike)
				break
			}
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

	var privKeyB64, pubKeyB64 string

	if pubkey != "" {
		pubKeyB64 = pubkey
		if debug {
			fmt.Printf("[DEBUG] Using supplied public key for certificate requests: %s\n", pubKeyB64)
		}
	} else {
		var genErr error
		privKeyB64, pubKeyB64, genErr = generateED25519()
		if genErr != nil {
			return genErr
		}
		fmt.Printf("Privkey = %s\n", privKeyB64)
		fmt.Printf("Pubkey = %s\n", pubKeyB64)
		fmt.Println()
	}

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
			processCertificate(cert, pubKeyB64, fmt.Sprintf("%d", bike.BikeID), customerUUID, bikes, debug)
		}
	}
	return nil
}
