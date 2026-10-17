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
// It does not request certificates itself.
func ShowKeys(email, mode, bikeFilter string, debug, noCache bool) error {
	authToken, _, _, err := resolveTokens(email, "", debug, noCache)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	customerData, err := fetchCustomerData(authToken, debug)
	if err != nil {
		return fmt.Errorf("failed to get customer data: %w", err)
	}

	candidates := filterKeyBikes(customerData.Data.BikeDetails, mode)
	if len(candidates) == 0 {
		if mode == ShowKeysStatic {
			fmt.Println("No bikes with a BLE encryption key found (S2/S3/S4 and older)")
		} else {
			fmt.Println("No static bikes found (S5/A5 and S6 use certificates and have no BLE key)")
		}
		return nil
	}

	// Reuse the regular bike selection (-bikes all / IDs / frame numbers / ask)
	list := make([]BikeData, len(candidates))
	for i, d := range candidates {
		list[i] = BikeData{Name: d.Name, BikeID: d.BikeID, FrameNumber: d.FrameNumber, BleProfile: d.BleProfile}
	}
	selected, err := selectBikes(list, bikeFilter)
	if err != nil {
		return err
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
			secret := d.Key.EncryptionKey
			if secret == "" {
				secret = "not available"
			}
			fmt.Printf("bikeName: %s\n", d.Name)
			fmt.Printf("frameNumber: %s\n", d.FrameNumber)
			fmt.Printf("macAddress: %s\n", d.MacAddress)
			fmt.Printf("bleSecret: %s\n", secret)
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
