package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"
)

func main() {
	version := flag.Bool("version", false, "Print version information")
	genkey := flag.Bool("genkey", false, "Generate Ed25519 key pair and exit")
	cert := flag.String("cert", "", "Base64 encoded certificate string")
	pubkey := flag.String("pubkey", "", "Base64 encoded public key string (optional)")
	bikeid := flag.String("bikeid", "", "Bike ID to verify (optional)")
	email := flag.String("email", "", "VanMoof email address (optional)")
	bikes := flag.String("bikes", "all", "Bikes to fetch certificates for: 'all', bike IDs (comma-separated), or 'ask' to be prompted")
	debug := flag.Bool("debug", false, "Enable debug output")
	sudo := flag.Bool("sudo", false, "Skip all validation checks")
	flag.Parse()

	if *debug {
		fmt.Printf("[DEBUG] Flags: version=%v, genkey=%v, cert='%s', pubkey='%s', bikeid='%s', email='%s', bikes='%s', sudo=%v\n", *version, *genkey, *cert, *pubkey, *bikeid, *email, *bikes, *sudo)
	}

	if *version {
		fmt.Println("vanmoof-certificates version", Version)
		fmt.Printf("OS: %s, Arch: %s, Go: %s, CPUs: %d, Compiler: %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), runtime.Compiler)
		return
	}

	if genkey != nil && *genkey {
		privKeyB64, pubKeyB64, err := generateED25519()
		if err != nil {
			fmt.Printf("Error generating key pair: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Privkey = %s\n", privKeyB64)
		fmt.Printf("Pubkey = %s\n", pubKeyB64)
		return
	}

	// Validate cert if provided
	if *cert != "" {
		if !*sudo && !isValidBase64(*cert) {
			fmt.Println("Error: Invalid base64 certificate string")
			return
		}
	}

	// Validate pubkey if provided
	if *pubkey != "" {
		if !*sudo && !isValidEd25519PublicKey(*pubkey) {
			fmt.Println("Error: Invalid Ed25519 public key. Must be base64-encoded 32 or 33 bytes")
			return
		}
	}

	// Validate bikeid if provided
	if *bikeid != "" {
		if !*sudo && !isValidBikeID(*bikeid) {
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
		if !*sudo && !isValidEmail(emailInput) {
			fmt.Printf("Error: Invalid email address '%s'\n", emailInput)
			return
		}

		// Get password from env or prompt
		passwordInput := os.Getenv("VANMOOF_PASSWORD")
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

		if err := getCert(emailInput, passwordInput, *bikes, *pubkey, *debug); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		return
	}

	processCertificate(*cert, *pubkey, *bikeid, "", nil, *debug)
}
