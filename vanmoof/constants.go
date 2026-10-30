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

// bleProfileModel maps BLE profiles to human-readable model names. A profile covers both
// frame shapes, S and X (see bikeModel).
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

// bleProfileFindMy is whether the bikes of a BLE profile work with Apple's Find My: the
// S3/X3 of ELECTRIFIED_2021 do, the ones of ELECTRIFIED_2020 and the older ones don't. A
// profile that isn't here isn't known either way.
var bleProfileFindMy = map[string]bool{
	"SMARTBIKE_2016":   false,
	"SMARTBIKE_2018":   false,
	"ELECTRIFIED_2016": false,
	"ELECTRIFIED_2017": false,
	"ELECTRIFIED_2018": false,
	"ELECTRIFIED_2020": false,
	"ELECTRIFIED_2021": true,
}

// sModelRegexp and xModelRegexp are the parts of a model like "S3/X3" or "Smart S/X" to
// remove for its S and its X frame shape
var (
	sModelRegexp = regexp.MustCompile(`/X\d*`)
	xModelRegexp = regexp.MustCompile(`S\d*/`)
)

// frameNumberRegexp matches SA5 and S6 frame numbers (frameNumberPattern)
var frameNumberRegexp = regexp.MustCompile(frameNumberPattern)

// s6FrameNumberRegexp matches S6 frame numbers (5 letters + 6 digits + 2 letters). Some
// SA5 frame numbers match too, so it's only a fallback when the BLE profile isn't known.
var s6FrameNumberRegexp = regexp.MustCompile(`^[A-Z]{5}\d{6}[A-Z]{2}$`)

// anyFrameNumberRegexp loosely matches the frame number of any generation: older bikes
// use other formats than SA5/S6 (e.g. 3 letters + 7 digits), so it only requires a
// letter, then letters and digits.
var anyFrameNumberRegexp = regexp.MustCompile(`^[A-Z][A-Z0-9]+$`)
