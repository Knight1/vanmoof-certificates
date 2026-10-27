package vanmoof

import (
	"fmt"
	"slices"
)

// Modes for ShowKeys
const (
	ShowKeysStatic = "static"
	ShowKeysAll    = "all"
)

func isCertOnlyProfile(profile string) bool {
	return slices.Contains(certOnlyBleProfiles, profile)
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
// instead of fetching them a second time. The keys, bike messages and certificates are
// saved in the cache.
func ShowKeys(email, mode string, opts Options) error {
	debug := opts.Debug
	s, customerData, err := login(email, debug, opts.NoCache)
	if err != nil {
		return err
	}
	saveCustomerData(email, customerData, opts)
	tokens := s.Tokens()

	warnPendingInvitations(tokens.AuthToken, debug)

	if debug {
		fmt.Printf("[DEBUG] Customer UUID: %s\n", Redact(customerData.Data.UUID))
		debugPrintBikeProfiles(customerData.Data.Bikes)
	}

	account := loadAccount(email, opts)
	account.setBLEKeys(customerData.Data.BikeDetails)
	err = printStaticKeys(customerData.Data.BikeDetails, tokens.AuthToken, &account, opts)
	if err == nil && mode == ShowKeysAll {
		bikes := mergeSharedVehicles(customerData.Data.Bikes, customerData.Data.UUID, tokens.AppToken, debug)
		err = requestCertificates(bikes, customerData.Data.UUID, s, &account, opts)
	}
	saveAccount(email, account, opts)
	cacheRenewedTokens(email, tokens, s, debug, opts.NoCache)
	return err
}

// printStaticKeys prints the BLE encryption key (or bike message status) of the
// account's static (non-certificate) bikes matching -bikes, and records the bike messages
// in account.
func printStaticKeys(details []BikeDetail, authToken string, account *savedAccount, opts Options) error {
	debug := opts.Debug
	candidates := filterKeyBikes(details)
	if len(candidates) == 0 {
		fmt.Println("No static bikes found (S5/A5 and S6 use certificates and have no BLE key)")
		return nil
	}

	// Reuse the regular bike selection (-bikes all / IDs / frame numbers / ask)
	list := make([]Bike, len(candidates))
	for i, d := range candidates {
		list[i] = Bike{Name: d.Name, BikeID: d.BikeID, FrameNumber: d.FrameNumber, BleProfile: d.BleProfile}
	}
	selected, err := selectBikes(list, opts.BikeFilter)
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
					fmt.Printf("bikeMessage: couldn't check (%v)\n", ScrubText(err.Error()))
				} else if len(messages) > 0 {
					fmt.Printf("bikeMessage: %d message(s) waiting for delivery over BLE\n", len(messages))
				} else {
					fmt.Println("bikeMessage: none waiting")
				}
				if err == nil {
					account.setBikeMessages(d, messages)
				}
			}
			if debug {
				model := bleProfileModel[d.BleProfile]
				if model == "" {
					model = "unknown"
				}
				fmt.Printf("[DEBUG] bleProfile: %s (%s)\n", printable(d.BleProfile), model)
			}
			fmt.Println()
			break
		}
	}
	return nil
}
