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
// Static mode additionally skips bikes where the API returned no key.
func filterKeyBikes(details []BikeDetail, mode string) []BikeDetail {
	var out []BikeDetail
	for _, d := range details {
		if isCertOnlyProfile(d.BleProfile) {
			continue
		}
		if mode == ShowKeysStatic && d.Key.EncryptionKey == "" {
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
	authToken, appToken, _, err := resolveTokens(email, "", debug, noCache)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	customerData, err := fetchCustomerData(authToken, debug)
	if err != nil {
		return fmt.Errorf("failed to get customer data: %w", err)
	}

	printStaticKeys(customerData.Data.BikeDetails, mode, bikeFilter, authToken, debug)

	if mode != ShowKeysAll {
		return nil
	}

	warnPendingInvitations(authToken, debug)
	bikes := mergeSharedVehicles(customerData.Data.Bikes, customerData.Data.UUID, appToken, debug)
	return requestCertificates(bikes, customerData.Data.UUID, appToken, bikeFilter, pubkey, debug)
}

// printStaticKeys prints the BLE encryption key (or bike message status) of the
// account's static (non-certificate) bikes matching mode and bikeFilter.
func printStaticKeys(details []BikeDetail, mode, bikeFilter, authToken string, debug bool) {
	candidates := filterKeyBikes(details, mode)
	if len(candidates) == 0 {
		if mode == ShowKeysStatic {
			fmt.Println("No bikes with a BLE encryption key found (S2/S3/S4 and older)")
		} else {
			fmt.Println("No static bikes found (S5/A5 and S6 use certificates and have no BLE key)")
		}
		return
	}

	// Reuse the regular bike selection (-bikes all / IDs / frame numbers / ask)
	list := make([]BikeData, len(candidates))
	for i, d := range candidates {
		list[i] = BikeData{Name: d.Name, BikeID: d.BikeID, FrameNumber: d.FrameNumber, BleProfile: d.BleProfile}
	}
	selected, err := selectBikes(list, bikeFilter)
	if err != nil {
		fmt.Printf("Error selecting bikes: %v\n", err)
		return
	}
	if len(selected) == 0 {
		fmt.Println("No bikes selected")
		return
	}

	for _, sel := range selected {
		for _, d := range candidates {
			if d.BikeID != sel.BikeID {
				continue
			}
			secret := d.Key.EncryptionKey
			if secret == "" {
				secret = "not available"
			}
			fmt.Printf("bikeName: %s\n", d.Name)
			fmt.Printf("frameNumber: %s\n", d.FrameNumber)
			fmt.Printf("macAddress: %s\n", d.MacAddress)
			fmt.Printf("bleSecret: %s\n", secret)

			// No key on a BLEv2 bike means the key itself may be waiting as a bike
			// message, delivered the next time the bike connects over BLE.
			if d.Key.EncryptionKey == "" && d.MessagesViaBLE == "BLEv2" {
				messages, err := getBikeMessages(d.BikeID, authToken, debug)
				if err != nil {
					if debug {
						fmt.Printf("[DEBUG] Failed to check bike messages: %v\n", err)
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
}
