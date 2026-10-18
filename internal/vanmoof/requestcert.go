package vanmoof

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/term"
)

// resolveTokens tries cached tokens first, then falls back to password auth.
// skipCachedTokens is for when the server rejected the cached tokens: only the
// cached refresh token is tried then, before the password.
// Returns authToken, appToken, and whether the auth token came from the cache, where
// it's only checked for expiry (the server can still reject it if it was revoked early).
func resolveTokens(email, password string, skipCachedTokens, debug, noCache bool) (string, string, bool, error) {
	var cached *CachedTokens
	if !noCache {
		cached = loadTokenCache(email, debug)
	}
	if cached != nil && skipCachedTokens {
		cached = &CachedTokens{RefreshToken: cached.RefreshToken}
	}

	if cached != nil {
		// Try app token first (valid ~2 hours), as long as the auth token hasn't expired either
		if !isJWTExpired(cached.AppToken) && !isJWTExpired(cached.AuthToken) {
			if debug {
				fmt.Println("[DEBUG] Using cached app token")
			}
			return cached.AuthToken, cached.AppToken, true, nil
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
				return cached.AuthToken, appToken, true, nil
			}
			if debug {
				fmt.Printf("[DEBUG] Failed to get app token with cached auth token: %v\n", err)
			}
		}

		// Auth token expired or rejected — try refresh token
		if cached.RefreshToken != "" {
			if debug {
				fmt.Println("[DEBUG] Auth token expired or rejected, trying refresh token")
			}
			authToken, refreshToken, err := refreshAuthToken(cached.RefreshToken, debug)
			if err == nil {
				// Keep using the old refresh token unless the server rotated it
				if refreshToken == "" {
					refreshToken = cached.RefreshToken
				}
				appToken, err := getApplicationToken(authToken, debug)
				if err == nil {
					if !noCache {
						saveTokenCache(email, authToken, refreshToken, appToken, debug)
					}
					return authToken, appToken, false, nil
				}
				if debug {
					fmt.Printf("[DEBUG] Failed to get app token after refresh: %v\n", err)
				}
			} else if debug {
				fmt.Printf("[DEBUG] Refresh token failed: %v\n", err)
			}
		}

		if debug {
			fmt.Println("[DEBUG] All cached tokens expired or rejected, need password")
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
			return "", "", false, fmt.Errorf("error reading password: %w", err)
		}
		fmt.Println()
		password = string(passwordBytes)
	}
	if password == "" {
		return "", "", false, fmt.Errorf("password required")
	}

	authToken, refreshToken, err := authenticate(email, password, debug)
	if err != nil {
		return "", "", false, err
	}
	if authToken == "" {
		return "", "", false, fmt.Errorf("authentication returned empty token")
	}

	if debug {
		fmt.Printf("[DEBUG] Auth token received: %s...\n", authToken[:min(20, len(authToken))])
	}

	appToken, err := getApplicationToken(authToken, debug)
	if err != nil {
		return "", "", false, err
	}
	if appToken == "" {
		return "", "", false, fmt.Errorf("application token request returned empty token")
	}

	if !noCache {
		saveTokenCache(email, authToken, refreshToken, appToken, debug)
	}
	return authToken, appToken, false, nil
}

// login resolves the account's tokens and fetches its customer data, the first request
// that needs a valid auth token. Cached tokens are only checked for expiry locally, so
// if the server rejects them anyway (revoked early, e.g. after a password change), login
// retries once without them: with the refresh token first, then the password.
func login(email string, debug, noCache bool) (string, string, *CustomerData, error) {
	authToken, appToken, fromCache, err := resolveTokens(email, "", false, debug, noCache)
	if err != nil {
		return "", "", nil, fmt.Errorf("authentication failed: %w", err)
	}

	customerData, err := fetchCustomerData(authToken, debug)
	if err != nil && fromCache && isUnauthorized(err) {
		fmt.Println("Cached tokens were rejected by the server, logging in again")
		authToken, appToken, _, err = resolveTokens(email, "", true, debug, noCache)
		if err != nil {
			return "", "", nil, fmt.Errorf("authentication failed: %w", err)
		}
		customerData, err = fetchCustomerData(authToken, debug)
	}
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to get customer data: %w", err)
	}

	return authToken, appToken, customerData, nil
}

func GetCert(email, bikeFilter, pubkey string, debug, noCache bool) error {
	if debug {
		fmt.Println("[DEBUG] Starting authentication...")
	}

	authToken, appToken, customerData, err := login(email, debug, noCache)
	if err != nil {
		return err
	}

	if debug {
		fmt.Printf("[DEBUG] App token received: %s...\n", appToken[:min(20, len(appToken))])
	}

	warnPendingInvitations(authToken, debug)

	customerUUID, bikes := customerData.Data.UUID, customerData.Data.Bikes

	if debug {
		fmt.Printf("[DEBUG] Customer UUID: %s\n", customerUUID)
		fmt.Printf("[DEBUG] Retrieved %d owned bikes\n", len(bikes))
		debugPrintBikeProfiles(bikes)
	}

	bikes = mergeSharedVehicles(bikes, customerUUID, appToken, debug)

	return requestCertificates(bikes, customerUUID, appToken, bikeFilter, pubkey, debug)
}

// debugPrintBikeProfiles prints each bike's BLE profile and, if it's one we recognize,
// the model name we map it to (debug mode only; callers only call this under debug).
func debugPrintBikeProfiles(bikes []BikeData) {
	for _, b := range bikes {
		model := bleProfileModel[b.BleProfile]
		if model == "" {
			model = "unknown"
		}
		fmt.Printf("[DEBUG]   %s: %s (%s)\n", b.FrameNumber, b.BleProfile, model)
	}
}

// debugPrintVehicleAccessProfiles is debugPrintBikeProfiles for shared/guest bikes from
// the Vehicle Registry API, which come back as VehicleAccess rather than BikeData.
func debugPrintVehicleAccessProfiles(vehicles []VehicleAccess) {
	for _, v := range vehicles {
		model := bleProfileModel[v.BleProfile]
		if model == "" {
			model = "unknown"
		}
		fmt.Printf("[DEBUG]   %s: %s (%s)\n", v.VehicleID, v.BleProfile, model)
	}
}

// warnPendingInvitations prints a warning if the account has pending bike sharing
// invitations. A lookup failure is only surfaced in debug mode, since it isn't fatal.
func warnPendingInvitations(authToken string, debug bool) {
	pendingInvitations, err := getBikeSharingInvitations(authToken, debug)
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] Failed to check sharing invitations: %v\n", err)
		}
		return
	}
	if pendingInvitations > 0 {
		fmt.Printf("WARNING: You have %d pending bike sharing invitation(s)! Accept them in the VanMoof app first.\n", pendingInvitations)
	}
}

// mergeSharedVehicles appends shared/guest bikes from the Vehicle Registry API to
// bikes, skipping any already present as an owned bike.
func mergeSharedVehicles(bikes []BikeData, customerUUID, appToken string, debug bool) []BikeData {
	sharedVehicles, err := getSharedVehicles(customerUUID, appToken, debug)
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] Failed to fetch shared vehicles: %v\n", err)
		}
		return bikes
	}
	if debug {
		fmt.Printf("[DEBUG] Retrieved %d shared vehicles\n", len(sharedVehicles))
		debugPrintVehicleAccessProfiles(sharedVehicles)
	}

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
	return bikes
}

// requestCertificates filters bikes down to the certificate-based ones (SA5/S6),
// lets the user pick which to process, and requests + parses a certificate for each.
// It is shared by GetCert and ShowKeys (in "all" mode), which fetch the account's
// bikes once and pass them in here rather than each fetching them separately.
func requestCertificates(bikes []BikeData, customerUUID, appToken, bikeFilter, pubkey string, debug bool) error {
	// Filter for supported (certificate) bikes only
	var supported []BikeData
	for _, bike := range bikes {
		if isCertOnlyProfile(bike.BleProfile) {
			supported = append(supported, bike)
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
		checkCertificate(cert, pubKeyB64, &bike, customerUUID, bikes, debug)
	}
	return nil
}
