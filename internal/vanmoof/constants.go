package vanmoof

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

// bleProfileModel maps BLE profiles to human-readable model names
var bleProfileModel = map[string]string{
	"ELECTRIFIED_2022":         "SA5",
	"ELECTRIFIED_2023_TRACK_1": "SA5",
	"ELECTRIFIED_2025":         "S6",
}
