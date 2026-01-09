package main

const (
	ApiKey    = "fcb38d47-f14b-30cf-843b-26283f6a5819"
	UserAgent = "VanMoof/20 CFNetwork/1404.0.5 Darwin/22.3.0"

	// Frame number validation patterns for different bike models
	// SA5 (S5/A5) frame number pattern: 6 letters + 5 digits + 2 letters
	// I doubt SA6 is different so for now lets use it for both bikes.
	FrameNumberPattern = `^[A-Z]{6}\d{5}[A-Z]{2}$`
)

var SupportedBleProfiles = []string{
	"ELECTRIFIED_2022",
	"ELECTRIFIED_2023_TRACK_1",
	"ELECTRIFIED_2025",
}
