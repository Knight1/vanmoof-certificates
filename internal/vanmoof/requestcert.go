package vanmoof

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/term"
)

// resolveTokens tries cached tokens first, then falls back to password auth.
// Returns authToken, appToken, refreshToken.
func resolveTokens(email, password string, debug, noCache bool) (string, string, string, error) {
	var cached *CachedTokens
	if !noCache {
		cached = loadTokenCache(email, debug)
	}

	if cached != nil {
		// Try app token first (valid ~2 hours)
		if !isJWTExpired(cached.AppToken) {
			if debug {
				fmt.Println("[DEBUG] Using cached app token")
			}
			return cached.AuthToken, cached.AppToken, cached.RefreshToken, nil
		}

		// App token expired — try auth token (valid ~1 year)
		if !isJWTExpired(cached.AuthToken) {
			if debug {
				fmt.Println("[DEBUG] App token expired, refreshing with cached auth token")
			}
			appToken, err := getApplicationToken(cached.AuthToken, debug)
			if err == nil {
				if !noCache {
					saveTokenCache(email, cached.AuthToken, cached.RefreshToken, appToken, debug)
				}
				return cached.AuthToken, appToken, cached.RefreshToken, nil
			}
			if debug {
				fmt.Printf("[DEBUG] Failed to get app token with cached auth token: %v\n", err)
			}
		}

		// Auth token expired — try refresh token
		if cached.RefreshToken != "" {
			if debug {
				fmt.Println("[DEBUG] Auth token expired, trying refresh token")
			}
			authToken, err := refreshAuthToken(cached.RefreshToken, debug)
			if err == nil {
				appToken, err := getApplicationToken(authToken, debug)
				if err == nil {
					if !noCache {
						saveTokenCache(email, authToken, cached.RefreshToken, appToken, debug)
					}
					return authToken, appToken, cached.RefreshToken, nil
				}
				if debug {
					fmt.Printf("[DEBUG] Failed to get app token after refresh: %v\n", err)
				}
			} else if debug {
				fmt.Printf("[DEBUG] Refresh token failed: %v\n", err)
			}
		}

		if debug {
			fmt.Println("[DEBUG] All cached tokens expired, need password")
		}
	}

	// No valid cached tokens — need password
	if password == "" {
		password = os.Getenv("VANMOOF_PASSWORD")
	}
	if password == "" {
		fmt.Print("Enter VanMoof password: ")
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", "", "", fmt.Errorf("error reading password: %w", err)
		}
		fmt.Println()
		password = string(passwordBytes)
	}
	if password == "" {
		return "", "", "", fmt.Errorf("password required")
	}

	authToken, refreshToken, err := authenticate(email, password, debug)
	if err != nil {
		return "", "", "", err
	}
	if authToken == "" {
		return "", "", "", fmt.Errorf("authentication returned empty token")
	}

	if debug {
		fmt.Printf("[DEBUG] Auth token received: %s...\n", authToken[:min(20, len(authToken))])
	}

	appToken, err := getApplicationToken(authToken, debug)
	if err != nil {
		return "", "", "", err
	}
	if appToken == "" {
		return "", "", "", fmt.Errorf("application token request returned empty token")
	}

	if !noCache {
		saveTokenCache(email, authToken, refreshToken, appToken, debug)
	}
	return authToken, appToken, refreshToken, nil
}

func GetCert(email, bikeFilter, pubkey string, debug, noCache bool) error {
	if debug {
		fmt.Println("[DEBUG] Starting authentication...")
	}

	authToken, appToken, _, err := resolveTokens(email, "", debug, noCache)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	if debug {
		fmt.Printf("[DEBUG] App token received: %s...\n", appToken[:min(20, len(appToken))])
	}

	// Check for pending bike sharing invitations
	pendingInvitations, err := getBikeSharingInvitations(authToken, debug)
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] Failed to check sharing invitations: %v\n", err)
		}
	} else if pendingInvitations > 0 {
		fmt.Printf("WARNING: You have %d pending bike sharing invitation(s)! Accept them in the VanMoof app first.\n", pendingInvitations)
	}

	// Get customer data (bikes)
	customerUUID, bikes, err := getCustomerData(authToken, debug)
	if err != nil {
		return fmt.Errorf("failed to get customer data: %w", err)
	}

	if debug {
		fmt.Printf("[DEBUG] Customer UUID: %s\n", customerUUID)
		fmt.Printf("[DEBUG] Retrieved %d owned bikes\n", len(bikes))
	}

	// Fetch shared bikes from vehicle registry
	sharedVehicles, err := getSharedVehicles(customerUUID, appToken, debug)
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] Failed to fetch shared vehicles: %v\n", err)
		}
	} else if debug {
		fmt.Printf("[DEBUG] Retrieved %d shared vehicles\n", len(sharedVehicles))
	}

	// Convert shared vehicles to BikeData and merge
	for _, v := range sharedVehicles {
		// Skip if we already have this bike as an owned bike
		alreadyOwned := false
		for _, b := range bikes {
			if b.FrameNumber == v.VehicleID {
				alreadyOwned = true
				break
			}
		}
		if alreadyOwned {
			continue
		}

		bikes = append(bikes, BikeData{
			Name:        v.Name + " (shared by " + v.OwnerName + ")",
			FrameNumber: v.VehicleID,
			BleProfile:  v.BleProfile,
		})
	}

	// Filter for supported bikes only
	var supported []BikeData
	for _, bike := range bikes {
		for _, profile := range supportedBleProfiles {
			if bike.BleProfile == profile {
				supported = append(supported, bike)
				break
			}
		}
	}

	if len(supported) == 0 {
		fmt.Println("No supported bikes found (SA5/S6)")
		return nil
	}

	// Filter bikes based on user selection
	selectedBikes, err := selectBikes(supported, bikeFilter)
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
		privKeyB64, pubKeyB64, genErr = GenerateED25519()
		if genErr != nil {
			return genErr
		}
		fmt.Printf("Privkey = %s\n", privKeyB64)
		fmt.Printf("Pubkey = %s\n", pubKeyB64)
		fmt.Println()
	}

	// Process each selected bike and create certificate
	for _, bike := range selectedBikes {
		if bike.BikeID != 0 {
			fmt.Printf("Bike ID: %d\n", bike.BikeID)
		}
		fmt.Printf("Name: %s\n", bike.Name)
		fmt.Printf("Frame number: %s\n", bike.FrameNumber)
		model := bleProfileModel[bike.BleProfile]
		if model == "" {
			model = bike.BleProfile
		}
		fmt.Printf("Model: %s\n", model)

		if debug {
			fmt.Printf("[DEBUG] Creating certificate for %s\n", bike.FrameNumber)
		}

		certResp, err := createCertificate(bike.FrameNumber, pubKeyB64, appToken, debug)
		if err != nil {
			fmt.Printf("Failed to create certificate: %v\n", err)
			continue
		}

		// Check if response contains an error
		var respData map[string]interface{}
		if err := json.Unmarshal([]byte(certResp), &respData); err != nil {
			fmt.Printf("Failed to parse certificate response: %v\n", err)
			continue
		}

		if _, hasErr := respData["err"]; hasErr {
			fmt.Printf("Certificate error: %v\n", certResp)
			continue
		}

		fmt.Println("Certificate:")
		fmt.Println(certResp)

		// Parse the certificate
		cert, ok := respData["certificate"].(string)
		if !ok {
			fmt.Println("Certificate response missing 'certificate' field")
			continue
		}
		fmt.Println("Parsing certificate...")
		bikeIDStr := bike.FrameNumber
		if bike.BikeID != 0 {
			bikeIDStr = fmt.Sprintf("%d", bike.BikeID)
		}
		ProcessCertificate(cert, pubKeyB64, bikeIDStr, customerUUID, bikes, debug)
	}
	return nil
}
