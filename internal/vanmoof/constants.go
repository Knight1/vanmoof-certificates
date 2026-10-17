package vanmoof

import "regexp"

const (
	// API key number 3
	apiKey = "fcb38d47-f14b-30cf-843b-26283f6a5819"

	// Frame number validation patterns for different bike models
	// SA5 (S5/A5): 6 letters + 5 digits + 2 letters (e.g. SVTBKL00063OA)
	// S6: 5 letters + 6 digits + 2 letters (e.g. TVSEF300106TA)
	frameNumberPattern = `^[A-Z]{5,6}\d{5,6}[A-Z]{2}$`

	apiBaseURL             = "https://api.vanmoof-api.com/v8"
	bikeApiBaseURL         = "https://bikeapi.production.vanmoof.cloud"
	vehicleRegistryBaseURL = "https://vehicleregistry.production.vanmoof.cloud"

	Version = "1.1.0"
)

var supportedBleProfiles = []string{
	"ELECTRIFIED_2022",
	"ELECTRIFIED_2023_TRACK_1",
	"ELECTRIFIED_2025",
}

// certOnlyBleProfiles are the profiles that authenticate with certificates and
// never use the BLE encryption key from getCustomerData (S5/A5 and S6).
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

// s6FrameNumberRegexp matches S6 frame numbers (5 letters + 6 digits + 2 letters)
var s6FrameNumberRegexp = regexp.MustCompile(`^[A-Z]{5}\d{6}[A-Z]{2}$`)
