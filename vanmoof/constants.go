package vanmoof

import "regexp"

const (
	// API key number 3
	apiKey = "fcb38d47-f14b-30cf-843b-26283f6a5819"

	// Frame number validation patterns for different bike models
	// SA5 (S5/A5): 6 letters + 5 digits + 2 letters (e.g. SVTBKLdddddOA), some 5 + 6 like S6
	// S6: 5 letters + 6 digits + 2 letters (e.g. TVSEFddddddTA)
	frameNumberPattern = `^[A-Z]{5,6}\d{5,6}[A-Z]{2}$`

	apiBaseURL             = "https://api.vanmoof-api.com/v8"
	bikeApiBaseURL         = "https://bikeapi.production.vanmoof.cloud"
	vehicleRegistryBaseURL = "https://vehicleregistry.production.vanmoof.cloud"

	Version = "1.1.0"
)

// certOnlyBleProfiles are the profiles that authenticate with certificates and
// never use the BLE encryption key from getCustomerData (S5/A5 and S6). They are
// both the bikes certificates are requested for and the ones -show-keys skips.
var certOnlyBleProfiles = []string{
	"ELECTRIFIED_2022",
	"ELECTRIFIED_2025",
}

// bleProfileModel maps BLE profiles to human-readable model names
var bleProfileModel = map[string]string{
	"SMARTBIKE_2016":           "Smartbike",
	"SMARTBIKE_2018":           "Smart S/X",
	"ELECTRIFIED_2016":         "S/X",
	"ELECTRIFIED_2017":         "S/X",
	"ELECTRIFIED_2018":         "S2/X2",
	"ELECTRIFIED_2020":         "S3/X3",
	"ELECTRIFIED_2021":         "S3/X3",
	"ELECTRIFIED_2022":         "SA5",
	"ELECTRIFIED_2023_TRACK_1": "S4/X4",
	"ELECTRIFIED_2023_TRACK1":  "S4/X4",
	"ELECTRIFIED_2025":         "S6",
}

// s6FrameNumberRegexp matches S6 frame numbers (5 letters + 6 digits + 2 letters). Some
// SA5 frame numbers match too, so it's only a fallback when the BLE profile isn't known.
var s6FrameNumberRegexp = regexp.MustCompile(`^[A-Z]{5}\d{6}[A-Z]{2}$`)

// anyFrameNumberRegexp loosely matches the frame number of any generation: older bikes
// use other formats than SA5/S6 (e.g. 3 letters + 7 digits), so it only requires a
// letter, then letters and digits.
var anyFrameNumberRegexp = regexp.MustCompile(`^[A-Z][A-Z0-9]+$`)
