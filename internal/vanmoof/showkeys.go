package vanmoof

import "fmt"

// Modes for ShowKeys
const (
	ShowKeysStatic = "static"
	ShowKeysAll    = "all"
)

func isCertOnlyProfile(profile string) bool {
	for _, p := range certOnlyBleProfiles {
		if p == profile {
			return true
		}
	}
	return false
}

// filterKeyBikes skips certificate-only bikes (S5/A5, S6), which have no BLE key.
// A bike with no key yet is kept, in both modes: it still needs to be checked for a
// pending key delivery via getBikeMessages (see printStaticKeys), so it can't be
// dropped here just because the key itself hasn't arrived.
func filterKeyBikes(details []BikeDetail) []BikeDetail {
	var out []BikeDetail
	for _, d := range details {
		if isCertOnlyProfile(d.BleProfile) {
			continue
		}
		out = append(out, d)
	}
	return out
}

// ShowKeys prints the BLE encryption key of the account's static (non-certificate) bikes.
// In "all" mode it additionally requests certificates for the certificate-based bikes
// (SA5/S6), reusing the authentication and customer data already fetched for the keys
// instead of fetching them a second time.
func ShowKeys(email, mode, bikeFilter, pubkey string, debug, noCache bool) error {
	authToken, appToken, customerData, err := login(email, debug, noCache)
	if err != nil {
		return err
	}

	warnPendingInvitations(authToken, debug)

	if debug {
		fmt.Printf("[DEBUG] Customer UUID: %s\n", Redact(customerData.Data.UUID))
		fmt.Printf("[DEBUG] Retrieved %d owned bikes\n", len(customerData.Data.Bikes))
		debugPrintBikeProfiles(customerData.Data.Bikes)
	}

	if err := printStaticKeys(customerData.Data.BikeDetails, bikeFilter, authToken, debug); err != nil {
		return err
	}

	if mode != ShowKeysAll {
		return nil
	}

	bikes := mergeSharedVehicles(customerData.Data.Bikes, customerData.Data.UUID, appToken, debug)
	return requestCertificates(bikes, customerData.Data.UUID, appToken, bikeFilter, pubkey, debug)
}

// printStaticKeys prints the BLE encryption key (or bike message status) of the
// account's static (non-certificate) bikes matching bikeFilter.
func printStaticKeys(details []BikeDetail, bikeFilter, authToken string, debug bool) error {
	candidates := filterKeyBikes(details)
	if len(candidates) == 0 {
		fmt.Println("No static bikes found (S5/A5 and S6 use certificates and have no BLE key)")
		return nil
	}

	// Reuse the regular bike selection (-bikes all / IDs / frame numbers / ask)
	list := make([]BikeData, len(candidates))
	for i, d := range candidates {
		list[i] = BikeData{Name: d.Name, BikeID: d.BikeID, FrameNumber: d.FrameNumber, BleProfile: d.BleProfile}
	}
	selected, err := selectBikes(list, bikeFilter)
	if err != nil {
		return fmt.Errorf("failed to select bikes: %w", err)
	}
	if len(selected) == 0 {
		fmt.Println("No bikes selected")
		return nil
	}

	for _, sel := range selected {
		for _, d := range candidates {
			if d.BikeID != sel.BikeID {
				continue
			}
			secret := Redact(d.Key.EncryptionKey)
			if secret == "" {
				secret = "not available"
			}
			fmt.Printf("bikeName: %s\n", Redact(d.Name))
			fmt.Printf("frameNumber: %s\n", RedactID(d.FrameNumber))
			fmt.Printf("macAddress: %s\n", Redact(d.MacAddress))
			fmt.Printf("bleSecret: %s\n", secret)

			// No key set yet on a non-certificate (pre-S5) bike means the key itself may
			// be waiting as a bike message, delivered next time the bike connects over BLE.
			// This isn't limited to a few known profiles: every pre-S5 generation uses a
			// static key the same way, server-side, regardless of its exact bleProfile string.
			if d.Key.EncryptionKey == "" && !isCertOnlyProfile(d.BleProfile) {
				messages, err := getBikeMessages(d.BikeID, authToken, debug)
				if err != nil {
					if debug {
						fmt.Printf("[DEBUG] Failed to check bike messages: %v\n", ScrubText(err.Error()))
					}
				} else if len(messages) > 0 {
					fmt.Printf("bikeMessage: %d message(s) waiting for delivery over BLE\n", len(messages))
				} else {
					fmt.Println("bikeMessage: none waiting")
				}
			}
			if debug {
				model := bleProfileModel[d.BleProfile]
				if model == "" {
					model = "unknown"
				}
				fmt.Printf("[DEBUG] bleProfile: %s (%s)\n", d.BleProfile, model)
			}
			fmt.Println()
			break
		}
	}
	return nil
}
