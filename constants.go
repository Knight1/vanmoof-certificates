package main

const (
	// API key number 3
	ApiKey = "fcb38d47-f14b-30cf-843b-26283f6a5819"

	// Frame number validation patterns for different bike models
	// SA5 (S5/A5) frame number pattern: 1 letter (S for S5 and A for A5) + 4 letters + 5 digits + 2 letters (possibly always OA for the SA5)
	// I doubt SA6 is different so for now lets use it for both bikes.
	FrameNumberPattern = `^[A-Z]{6}\d{5}[A-Z]{2}$`

	ApiBaseURL     = "https://api.vanmoof-api.com/v8"
	BikeApiBaseURL = "https://bikeapi.production.vanmoof.cloud"
	Version        = "1.0.0"
)

var SupportedBleProfiles = []string{
	"ELECTRIFIED_2022",
	"ELECTRIFIED_2023_TRACK_1",
	"ELECTRIFIED_2025",
}
