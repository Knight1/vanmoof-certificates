package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"net/mail"
	"os"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/term"
)

func main() {
	version := flag.Bool("version", false, "Print version information")
	cert := flag.String("cert", "", "Base64 encoded certificate string")
	pubkey := flag.String("pubkey", "", "Base64 encoded public key string (optional)")
	bikeid := flag.String("bikeid", "", "Bike ID to verify (optional)")
	email := flag.String("email", "", "VanMoof email address (optional)")
	password := flag.String("password", "", "VanMoof password (optional)")
	bikes := flag.String("bikes", "all", "Bikes to fetch certificates for: 'all', bike IDs (comma-separated), or 'ask' to be prompted")
	debug := flag.Bool("debug", false, "Enable debug output")
	flag.Parse()

	if *version {
		fmt.Println("vanmoof-certificates version", Version)
		fmt.Printf("OS: %s, Arch: %s, Go: %s, CPUs: %d, Compiler: %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), runtime.Compiler)
		return
	}

	// Validate cert if provided
	if *cert != "" {
		if !isValidBase64(*cert) {
			fmt.Println("Error: Invalid base64 certificate string")
			return
		}
	}

	// Validate pubkey if provided
	if *pubkey != "" {
		if !isValidBase64(*pubkey) {
			fmt.Println("Error: Invalid base64 public key string")
			return
		}
	}

	// Validate bikeid if provided
	if *bikeid != "" {
		if !isValidBikeID(*bikeid) {
			fmt.Printf("Error: Invalid bike ID '%s'. Must be a numeric ID or valid frame number pattern\n", *bikeid)
			return
		}
	}

	// Validate bikes parameter
	if *bikes != "all" && *bikes != "ask" {
		// Check if it's comma-separated bike IDs
		bikeIDs := strings.Split(*bikes, ",")
		for _, id := range bikeIDs {
			id = strings.TrimSpace(id)
			if id == "" {
				fmt.Println("Error: Empty bike ID in bikes list")
				return
			}
			var numericID uint32
			if _, err := fmt.Sscanf(id, "%d", &numericID); err != nil {
				fmt.Printf("Error: Invalid bike ID '%s' in bikes list. Must be numeric\n", id)
				return
			}
		}
	}

	if *cert == "" {
		// Get email from flag or prompt
		emailInput := *email
		if emailInput == "" {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Enter VanMoof email: ")
			var err error
			emailInput, err = reader.ReadString('\n')
			if err != nil {
				fmt.Printf("Error reading email: %v\n", err)
				return
			}
			emailInput = strings.TrimSpace(emailInput)
		}

		// Validate email
		if !isValidEmail(emailInput) {
			fmt.Printf("Error: Invalid email address '%s'\n", emailInput)
			return
		}

		// Get password from flag or prompt
		passwordInput := *password
		if passwordInput == "" {
			fmt.Print("Enter VanMoof password: ")
			passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				fmt.Printf("\nError reading password: %v\n", err)
				return
			}
			fmt.Println()
			passwordInput = string(passwordBytes)
		}

		// Validate password
		if len(passwordInput) == 0 {
			fmt.Println("Error: Password cannot be empty")
			return
		}

		if err := getCert(emailInput, passwordInput, *bikes, *debug); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		return
	}

	processCertificate(*cert, *pubkey, *bikeid, "", nil, *debug)
}

// isValidEmail validates an email address
func isValidEmail(email string) bool {
	email = strings.TrimSpace(email)
	if email == "" {
		return false
	}
	_, err := mail.ParseAddress(email)
	return err == nil
}

// isValidBase64 validates a base64 string
func isValidBase64(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// isValidBikeID validates a bike ID (numeric or frame number)
func isValidBikeID(bikeID string) bool {
	bikeID = strings.TrimSpace(bikeID)
	if bikeID == "" {
		return false
	}

	// Check if it's a numeric ID
	var numericID uint32
	if _, err := fmt.Sscanf(bikeID, "%d", &numericID); err == nil {
		return true
	}

	// Check if it's a valid frame number pattern
	matched, err := regexp.MatchString(FrameNumberPattern, bikeID)
	if err != nil {
		return false
	}

	return matched
}
