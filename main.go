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
	cert := flag.String("cert", "", "Base64 encoded certificate string")
	pubkey := flag.String("pubkey", "", "Base64 encoded public key string (optional)")
	bikeid := flag.String("bikeid", "", "Bike ID to verify (optional)")
	email := flag.String("email", "", "VanMoof email address (optional)")
	password := flag.String("password", "", "VanMoof password (optional)")
	debug := flag.Bool("debug", false, "Enable debug output")
	flag.Parse()

	if *version {
		fmt.Println("vanmoof-certificates version", Version)
		fmt.Printf("OS: %s, Arch: %s, Go: %s, CPUs: %d, Compiler: %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), runtime.Compiler)
		return
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

		if err := getCert(emailInput, passwordInput, *debug); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		return
	}

	processCertificate(*cert, *pubkey, *bikeid)
}
