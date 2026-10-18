package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/Knight1/vanmoof-certificates/vanmoof"
)

// Exit statuses: 1 when something failed, 2 for invalid flags (as the flag package does)
const (
	exitFailure = 1
	exitUsage   = 2
)

func main() {
	version := flag.Bool("version", false, "Print version information")
	genkey := flag.Bool("genkey", false, "Generate Ed25519 key pair and exit")
	cert := flag.String("cert", "", "Base64 encoded certificate string")
	pubkey := flag.String("pubkey", "", "Base64 encoded public key string (optional)")
	frameNumber := flag.String("framenumber", "", "Frame number to verify the -cert certificate against (optional)")
	email := flag.String("email", "", "VanMoof email address (optional)")
	bikes := flag.String("bikes", "all", "Bikes to process: 'all', bike IDs or frame numbers (comma-separated), or 'ask' to be prompted")
	showKeys := flag.String("show-keys", "", "Show BLE encryption keys instead of requesting certificates: 'static' (only the keys) or 'all' (keys, and certificates for the certificate bikes as usual)")
	debug := flag.Bool("debug", false, "Enable debug output (tokens and keys stay hidden, see -show-everything)")
	redact := flag.Bool("redact", false, "Hide secrets and personal data in all output, e.g. to share it in an issue")
	showEverything := flag.Bool("show-everything", false, "With -debug, also show the tokens and keys it hides (never share this output)")
	newKey := flag.Bool("new-key", false, "Request the certificates for a new key pair, which replaces the saved one")
	showSaved := flag.Bool("show-saved", false, "Show what the cache holds for the account: key pair, certificates, BLE keys, bike messages and customer data")
	invitations := flag.String("invitations", "", "Bike sharing invitations: 'list' them, or 'accept' or 'decline' them, asking which; 'accept=all', or numbers or GUIDs after '=', choose them")
	cleartextKeys := flag.Bool("cleartext-keys", false, "Without VANMOOF_CACHE_KEY, save the key pair, certificates, BLE keys and customer data unencrypted (else they're only saved encrypted)")
	noCache := flag.Bool("no-cache", false, "Do not read or write the cache (tokens, key pair, certificates, BLE keys, bike messages, customer data)")
	sudo := flag.Bool("sudo", false, "Skip all validation checks")
	flag.Parse()

	// Spaces around a value, e.g. from copying it, aren't part of it. Trimming here means
	// the validation below checks exactly what's used.
	for _, s := range []*string{cert, pubkey, frameNumber, email} {
		*s = strings.TrimSpace(*s)
	}

	if *redact && *showEverything {
		fmt.Println("Error: -redact and -show-everything cannot be combined")
		os.Exit(exitUsage)
	}
	if *showEverything && !*debug {
		fmt.Println("Error: -show-everything only works with -debug")
		os.Exit(exitUsage)
	}
	vanmoof.SetRedaction(*redact, *showEverything)

	if *debug {
		bikesShown := *bikes
		if bikesShown != "all" && bikesShown != "ask" {
			bikesShown = vanmoof.RedactID(bikesShown)
		}
		fmt.Printf("[DEBUG] Flags: version=%v, genkey=%v, cert='%s', pubkey='%s', framenumber='%s', email='%s', bikes='%s', show-keys='%s', new-key=%v, show-saved=%v, invitations='%s', cleartext-keys=%v, no-cache=%v, sudo=%v, redact=%v, show-everything=%v\n",
			*version, *genkey, vanmoof.Redact(*cert), vanmoof.Redact(*pubkey), vanmoof.RedactID(*frameNumber), vanmoof.Redact(*email), bikesShown, *showKeys, *newKey, *showSaved, vanmoof.ScrubText(*invitations), *cleartextKeys, *noCache, *sudo, *redact, *showEverything)
	}

	if *version {
		fmt.Println("vanmoof-certificates version", vanmoof.Version)
		fmt.Printf("OS: %s, Arch: %s, Go: %s, CPUs: %d, Compiler: %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), runtime.Compiler)
		return
	}

	if genkey != nil && *genkey {
		privKeyB64, pubKeyB64, err := vanmoof.GenerateED25519()
		if err != nil {
			fmt.Printf("Error generating key pair: %v\n", err)
			os.Exit(exitFailure)
		}
		fmt.Printf("Privkey = %s\n", vanmoof.Redact(privKeyB64))
		fmt.Printf("Pubkey = %s\n", vanmoof.Redact(pubKeyB64))
		return
	}

	// Validate show-keys if provided
	if *showKeys != "" {
		if *showKeys != vanmoof.ShowKeysStatic && *showKeys != vanmoof.ShowKeysAll {
			fmt.Printf("Error: Invalid -show-keys value '%s'. Must be '%s' or '%s'\n", *showKeys, vanmoof.ShowKeysStatic, vanmoof.ShowKeysAll)
			os.Exit(exitUsage)
		}
		if *cert != "" {
			fmt.Println("Error: -show-keys cannot be combined with -cert")
			os.Exit(exitUsage)
		}
	}

	if *newKey {
		if *pubkey != "" {
			fmt.Println("Error: -new-key and -pubkey cannot be combined")
			os.Exit(exitUsage)
		}
		if *cert != "" || *showKeys == vanmoof.ShowKeysStatic || *showSaved {
			fmt.Println("Error: -new-key only works when requesting certificates")
			os.Exit(exitUsage)
		}
	}
	invitationAction, invitationSelection, hasSelection := strings.Cut(*invitations, "=")
	if *invitations != "" {
		switch {
		case invitationAction != vanmoof.InvitationsList && invitationAction != vanmoof.InvitationsAccept && invitationAction != vanmoof.InvitationsDecline:
			fmt.Printf("Error: Invalid -invitations value '%s'. Must be '%s', '%s' or '%s'\n", vanmoof.ScrubText(*invitations), vanmoof.InvitationsList, vanmoof.InvitationsAccept, vanmoof.InvitationsDecline)
			os.Exit(exitUsage)
		case hasSelection && (invitationAction == vanmoof.InvitationsList || strings.TrimSpace(invitationSelection) == ""):
			fmt.Println("Error: -invitations takes the invitations after '=' only to accept or decline them, e.g. 'accept=all'")
			os.Exit(exitUsage)
		}
		if *cert != "" || *showKeys != "" || *showSaved || *pubkey != "" || *newKey {
			fmt.Println("Error: -invitations cannot be combined with -cert, -show-keys, -show-saved, -pubkey or -new-key")
			os.Exit(exitUsage)
		}
	}

	if *cleartextKeys && *noCache {
		fmt.Println("Error: -cleartext-keys and -no-cache cannot be combined")
		os.Exit(exitUsage)
	}
	if *showSaved && (*cert != "" || *showKeys != "" || *pubkey != "" || *noCache) {
		fmt.Println("Error: -show-saved cannot be combined with -cert, -show-keys, -pubkey or -no-cache")
		os.Exit(exitUsage)
	}

	// Validate cert if provided
	if *cert != "" {
		if !*sudo && !vanmoof.IsValidBase64(*cert) {
			fmt.Println("Error: Invalid base64 certificate string")
			os.Exit(exitUsage)
		}
	}

	// Validate pubkey if provided
	if *pubkey != "" {
		if !*sudo && !vanmoof.IsValidEd25519PublicKey(*pubkey) {
			fmt.Println("Error: Invalid Ed25519 public key. Must be base64-encoded 32 or 33 bytes")
			os.Exit(exitUsage)
		}
	}

	// Validate framenumber if provided
	if *frameNumber != "" {
		if *cert == "" {
			fmt.Println("Error: -framenumber only works with -cert (use -bikes to pick bikes)")
			os.Exit(exitUsage)
		}
		if !*sudo && !vanmoof.ValidateFrameNumber(*frameNumber) {
			fmt.Printf("Error: Invalid frame number '%s'\n", vanmoof.RedactID(*frameNumber))
			os.Exit(exitUsage)
		}
	}

	// Validate bikes parameter
	if *bikes != "all" && *bikes != "ask" {
		for id := range strings.SplitSeq(*bikes, ",") {
			id = strings.TrimSpace(id)
			if id == "" {
				fmt.Println("Error: Empty bike ID in bikes list")
				os.Exit(exitUsage)
			}
			if _, ok := vanmoof.ParseBikeID(id); !ok {
				// Any generation's frame number, not just SA5/S6: -show-keys picks older bikes
				if !*sudo && !vanmoof.LooksLikeFrameNumber(id) {
					fmt.Printf("Error: Invalid bike ID '%s' in bikes list. Must be a numeric ID or frame number\n", vanmoof.RedactID(id))
					os.Exit(exitUsage)
				}
			}
		}
	}

	if *cert == "" {
		emailInput := *email
		if emailInput == "" {
			fmt.Print("Enter VanMoof email: ")
			var err error
			emailInput, err = vanmoof.ReadLine()
			if err != nil {
				fmt.Printf("Error reading email: %v\n", err)
				os.Exit(exitFailure)
			}
		}

		if !*sudo && !vanmoof.IsValidEmail(emailInput) {
			fmt.Printf("Error: Invalid email address '%s'\n", vanmoof.Redact(emailInput))
			os.Exit(exitUsage)
		}

		if *showSaved {
			if err := vanmoof.ShowSaved(emailInput, *debug); err != nil {
				fmt.Printf("Error: %v\n", vanmoof.ScrubText(err.Error()))
				os.Exit(exitFailure)
			}
			return
		}

		opts := vanmoof.Options{BikeFilter: *bikes, PublicKey: *pubkey, NewKey: *newKey, Debug: *debug, NoCache: *noCache, CleartextKeys: *cleartextKeys}
		if *invitations != "" {
			if err := vanmoof.Invitations(emailInput, invitationAction, strings.TrimSpace(invitationSelection), opts); err != nil {
				fmt.Printf("Error: %v\n", vanmoof.ScrubText(err.Error()))
				os.Exit(exitFailure)
			}
			return
		}

		if *showKeys != "" {
			// ShowKeys itself requests certificates too in "all" mode, reusing the
			// authentication and customer data it already fetched for the keys.
			if err := vanmoof.ShowKeys(emailInput, *showKeys, opts); err != nil {
				fmt.Printf("Error: %v\n", vanmoof.ScrubText(err.Error()))
				os.Exit(exitFailure)
			}
			return
		}

		if err := vanmoof.GetCert(emailInput, opts); err != nil {
			fmt.Printf("Error: %v\n", vanmoof.ScrubText(err.Error()))
			os.Exit(exitFailure)
		}
		return
	}

	if !vanmoof.ProcessCertificate(*cert, *pubkey, *frameNumber, *debug) {
		os.Exit(exitFailure)
	}
}
