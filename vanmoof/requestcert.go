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
// Returns the tokens, and whether the auth token came from the cache, where it's only
// checked for expiry (the server can still reject it if it was revoked early).
func resolveTokens(email, password string, skipCachedTokens, debug, noCache bool) (Tokens, bool, error) {
	var cached *Tokens
	if !noCache {
		cached = loadTokenCache(email, debug)
	}
	if cached != nil && skipCachedTokens {
		cached = &Tokens{RefreshToken: cached.RefreshToken}
	}

	if cached != nil {
		// Try app token first (valid ~2 hours), as long as the auth token hasn't expired either
		if !isJWTExpired(cached.AppToken) && !isJWTExpired(cached.AuthToken) {
			if debug {
				fmt.Println("[DEBUG] Using cached app token")
			}
			return *cached, true, nil
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
				return Tokens{AuthToken: cached.AuthToken, AppToken: appToken, RefreshToken: cached.RefreshToken}, true, nil
			}
			if debug {
				fmt.Printf("[DEBUG] Failed to get app token with cached auth token: %v\n", ScrubText(err.Error()))
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
					return Tokens{AuthToken: authToken, AppToken: appToken, RefreshToken: refreshToken}, false, nil
				}
				if debug {
					fmt.Printf("[DEBUG] Failed to get app token after refresh: %v\n", ScrubText(err.Error()))
				}
			} else if debug {
				fmt.Printf("[DEBUG] Refresh token failed: %v\n", ScrubText(err.Error()))
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
			return Tokens{}, false, fmt.Errorf("error reading password: %w", err)
		}
		fmt.Println()
		password = string(passwordBytes)
	}
	if password == "" {
		return Tokens{}, false, fmt.Errorf("password required")
	}

	s, err := passwordLogin(email, password, debug)
	if err != nil {
		return Tokens{}, false, err
	}

	if !noCache {
		saveTokenCache(email, s.tokens.AuthToken, s.tokens.RefreshToken, s.tokens.AppToken, debug)
	}
	return s.tokens, false, nil
}

// login resolves the account's tokens and fetches its customer data, the first request
// that needs a valid auth token. Cached tokens are only checked for expiry locally, so
// if the server rejects them anyway (revoked early, e.g. after a password change), login
// retries once without them: with the refresh token first, then the password.
func login(email string, debug, noCache bool) (*Session, *CustomerData, error) {
	tokens, fromCache, err := resolveTokens(email, "", false, debug, noCache)
	if err != nil {
		return nil, nil, fmt.Errorf("authentication failed: %w", err)
	}

	customerData, err := fetchCustomerData(tokens.AuthToken, debug)
	if err != nil && fromCache && isUnauthorized(err) {
		fmt.Println("Cached tokens were rejected by the server, logging in again")
		tokens, _, err = resolveTokens(email, "", true, debug, noCache)
		if err != nil {
			return nil, nil, fmt.Errorf("authentication failed: %w", err)
		}
		customerData, err = fetchCustomerData(tokens.AuthToken, debug)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get customer data: %w", err)
	}

	return &Session{tokens: tokens, userID: customerData.Data.UUID, debug: debug}, customerData, nil
}

// cacheRenewedTokens caches the session's tokens if it renewed them since they were before
func cacheRenewedTokens(email string, before Tokens, s *Session, debug, noCache bool) {
	if t := s.Tokens(); t != before && !noCache {
		saveTokenCache(email, t.AuthToken, t.RefreshToken, t.AppToken, debug)
	}
}

func GetCert(email, bikeFilter, pubkey string, debug, noCache bool) error {
	if debug {
		fmt.Println("[DEBUG] Starting authentication...")
	}

	s, customerData, err := login(email, debug, noCache)
	if err != nil {
		return err
	}
	tokens := s.Tokens()

	if debug {
		fmt.Printf("[DEBUG] App token received: %s\n", debugSecret(tokens.AppToken[:min(20, len(tokens.AppToken))]+"..."))
	}

	warnPendingInvitations(tokens.AuthToken, debug)

	customerUUID, bikes := customerData.Data.UUID, customerData.Data.Bikes

	if debug {
		fmt.Printf("[DEBUG] Customer UUID: %s\n", Redact(customerUUID))
		fmt.Printf("[DEBUG] Retrieved %d owned bikes\n", len(bikes))
		debugPrintBikeProfiles(bikes)
	}

	bikes = mergeSharedVehicles(bikes, customerUUID, tokens.AppToken, debug)

	err = requestCertificates(bikes, customerUUID, s, bikeFilter, pubkey, debug)
	cacheRenewedTokens(email, tokens, s, debug, noCache)
	return err
}

// debugPrintBikeProfiles prints each bike's BLE profile and, if it's one we recognize,
// the model name we map it to (debug mode only; callers only call this under debug).
func debugPrintBikeProfiles(bikes []Bike) {
	for _, b := range bikes {
		model := bleProfileModel[b.BleProfile]
		if model == "" {
			model = "unknown"
		}
		fmt.Printf("[DEBUG]   %s: %s (%s)\n", RedactID(b.FrameNumber), printable(b.BleProfile), model)
	}
}

// debugPrintVehicleAccessProfiles is debugPrintBikeProfiles for shared/guest bikes from
// the Vehicle Registry API, which come back as VehicleAccess rather than Bike.
func debugPrintVehicleAccessProfiles(vehicles []VehicleAccess) {
	for _, v := range vehicles {
		model := bleProfileModel[v.BleProfile]
		if model == "" {
			model = "unknown"
		}
		fmt.Printf("[DEBUG]   %s: %s (%s)\n", RedactID(v.VehicleID), printable(v.BleProfile), model)
	}
}

// warnPendingInvitations prints a warning if the account has pending bike sharing
// invitations. A lookup failure is only surfaced in debug mode, since it isn't fatal.
func warnPendingInvitations(authToken string, debug bool) {
	pendingInvitations, err := getBikeSharingInvitations(authToken, debug)
	if err != nil {
		fmt.Printf("WARNING: Couldn't check for pending bike sharing invitations: %v\n", ScrubText(err.Error()))
		return
	}
	if pendingInvitations > 0 {
		fmt.Printf("WARNING: You have %d pending bike sharing invitation(s)! Accept them in the VanMoof app first.\n", pendingInvitations)
	}
}

// mergeSharedVehicles appends shared/guest bikes from the Vehicle Registry API to
// bikes, skipping any already present as an owned bike.
func mergeSharedVehicles(bikes []Bike, customerUUID, appToken string, debug bool) []Bike {
	sharedVehicles, err := getSharedVehicles(customerUUID, appToken, debug)
	if err != nil {
		// Not fatal, the owned bikes still work, but without this a guest only sees no bikes
		fmt.Printf("WARNING: Couldn't look up the bikes shared with you: %v\n", ScrubText(err.Error()))
		return bikes
	}
	if debug {
		fmt.Printf("[DEBUG] Retrieved %d shared vehicles\n", len(sharedVehicles))
		debugPrintVehicleAccessProfiles(sharedVehicles)
	}
	return addSharedBikes(bikes, sharedVehicles)
}

// addSharedBikes appends the shared vehicles to bikes, skipping any already present as an
// owned bike
func addSharedBikes(bikes []Bike, sharedVehicles []VehicleAccess) []Bike {
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

		bikes = append(bikes, Bike{
			Name:        v.Name,
			FrameNumber: v.VehicleID,
			BleProfile:  v.BleProfile,
			Owner:       v.OwnerName,
		})
	}
	return bikes
}

// requestCertificates filters bikes down to the certificate-based ones (SA5/S6),
// lets the user pick which to process, and requests + parses a certificate for each.
// It is shared by GetCert and ShowKeys (in "all" mode), which fetch the account's
// bikes once and pass them in here rather than each fetching them separately.
func requestCertificates(bikes []Bike, customerUUID string, s *Session, bikeFilter, pubkey string, debug bool) error {
	// Filter for supported (certificate) bikes only
	var supported []Bike
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
			fmt.Printf("[DEBUG] Using supplied public key for certificate requests: %s\n", Redact(pubKeyB64))
		}
	} else {
		var genErr error
		privKeyB64, pubKeyB64, genErr = GenerateED25519()
		if genErr != nil {
			return genErr
		}
		fmt.Printf("Privkey = %s\n", Redact(privKeyB64))
		fmt.Printf("Pubkey = %s\n", Redact(pubKeyB64))
		fmt.Println()
	}

	// Process each selected bike and create certificate, counting the ones that fail
	failed := 0
	for _, bike := range selectedBikes {
		if bike.BikeID != 0 {
			fmt.Printf("Bike ID: %s\n", RedactID(fmt.Sprint(bike.BikeID)))
		}
		fmt.Printf("Name: %s\n", Redact(displayName(bike)))
		fmt.Printf("Frame number: %s\n", RedactID(bike.FrameNumber))
		fmt.Printf("Model: %s\n", printable(bike.Model()))

		if debug {
			fmt.Printf("[DEBUG] Creating certificate for %s\n", RedactID(bike.FrameNumber))
		}

		certResp, err := s.certificateResponse(bike, pubKeyB64)
		if err != nil {
			fmt.Printf("Failed to create certificate: %v\n", ScrubText(err.Error()))
			failed++
			continue
		}

		// Check if response contains an error
		var respData map[string]interface{}
		if err := json.Unmarshal([]byte(certResp), &respData); err != nil {
			fmt.Printf("Failed to parse certificate response: %v\n", ScrubText(err.Error()))
			failed++
			continue
		}

		if _, hasErr := respData["err"]; hasErr {
			fmt.Printf("Certificate error: %v\n", redactJSON(certResp))
			failed++
			continue
		}

		fmt.Println("Certificate:")
		fmt.Println(redactJSON(certResp))

		// Parse the certificate
		cert, ok := respData["certificate"].(string)
		if !ok {
			fmt.Println("Certificate response missing 'certificate' field")
			failed++
			continue
		}
		fmt.Println("Parsing certificate...")
		if !checkCertificate(cert, Expect{PublicKey: pubKeyB64, Bike: &bike, UserID: customerUUID, Bikes: bikes}, debug) {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d certificate(s) failed", failed, len(selectedBikes))
	}
	return nil
}
