package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"unicode"

	"github.com/Knight1/vanmoof-certificates/vanmoof"
)

// Exit statuses: 1 when something failed, 2 for invalid flags (as the flag package does)
const (
	exitFailure = 1
	exitUsage   = 2
)

// exit is os.Exit, which TestMainExits replaces to run main
var exit = os.Exit

// hardenMemory keeps secrets out of swap and core dumps (see main_harden_*.go); tests
// replace it with a no-op, since locking memory per test run is pointless and may fail
var hardenMemory = hardenMemoryImpl

func main() {
	exit(run(os.Args[1:]))
}

// run runs the tool with the command line arguments args, and returns its exit status
func run(args []string) int {
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.SetOutput(escaped{os.Stderr})
	version := flags.Bool("version", false, "Print version information")
	genkey := flags.Bool("genkey", false, "Generate Ed25519 key pair and exit")
	generate := flags.String("generate", "", "Generate a self-signed certificate from a JSON config file and exit (advanced: only for a bike whose firmware you've changed to trust your own signing key; see USAGE.md)")
	cert := flags.String("cert", "", "Base64 encoded certificate string")
	pubkey := flags.String("pubkey", "", "Base64 encoded public key string (optional)")
	frameNumber := flags.String("framenumber", "", "Frame number to verify the -cert certificate against (optional)")
	email := flags.String("email", "", "VanMoof email address (optional)")
	bikes := flags.String("bikes", "all", "Bikes to process: 'all', bike IDs or frame numbers (comma-separated), or 'ask' to be prompted")
	showKeys := flags.String("show-keys", "", "Show BLE encryption keys instead of requesting certificates: 'static' (only the keys) or 'all' (keys, and certificates for the certificate bikes as usual)")
	debug := flags.Bool("debug", false, "Enable debug output (tokens and keys stay hidden, see -show-everything)")
	redact := flags.Bool("redact", false, "Hide secrets and personal data in all output, e.g. to share it in an issue")
	showEverything := flags.Bool("show-everything", false, "With -debug, also show the tokens and keys it hides (never share this output)")
	newKey := flags.Bool("new-key", false, "Request the certificates for a new key pair, which replaces the saved one")
	showSaved := flags.Bool("show-saved", false, "Show what the cache holds for the account: key pair, certificates, BLE keys, bike messages and customer data")
	invitations := flags.String("invitations", "", "Bike sharing invitations: 'list' them, or 'accept' or 'decline' them, asking which; 'accept=all', or numbers or GUIDs after '=', choose them")
	cleartextKeys := flags.Bool("cleartext-keys", false, "Without VANMOOF_CACHE_KEY, save the key pair, certificates, BLE keys and customer data unencrypted (else they're only saved encrypted)")
	noCache := flags.Bool("no-cache", false, "Do not read or write the cache (tokens, key pair, certificates, BLE keys, bike messages, customer data)")
	allowUnknownRevocation := flags.Bool("allow-unknown-revocation", false, "Connect even when a VanMoof server's TLS certificate can't be confirmed unrevoked: neither OCSP nor the CRL vouches for it, or Mozilla's OneCRL couldn't be fetched or verified, e.g. with the CA's or Mozilla's servers unreachable (a revoked one is always refused)")
	sudo := flags.Bool("sudo", false, "Skip all validation checks")
	if err := flags.Parse(args); err != nil {
		// The flag package has printed the error and the usage (or only the usage, for -h)
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return exitUsage
	}

	// Spaces around a value, e.g. from copying it, aren't part of it. Trimming here means
	// the validation below checks exactly what's used.
	for _, s := range []*string{cert, pubkey, frameNumber, email} {
		*s = strings.TrimSpace(*s)
	}

	if *redact && *showEverything {
		fmt.Println("Error: -redact and -show-everything cannot be combined")
		return exitUsage
	}
	if *showEverything && !*debug {
		fmt.Println("Error: -show-everything only works with -debug")
		return exitUsage
	}
	vanmoof.SetRedaction(*redact, *showEverything)
	vanmoof.SetAllowUnknownRevocation(*allowUnknownRevocation)

	if *debug {
		bikesShown := *bikes
		if bikesShown != "all" && bikesShown != "ask" {
			bikesShown = vanmoof.RedactID(bikesShown)
		}
		fmt.Printf("[DEBUG] Flags: version=%v, genkey=%v, generate='%s', cert='%s', pubkey='%s', framenumber='%s', email='%s', bikes='%s', show-keys='%s', new-key=%v, show-saved=%v, invitations='%s', cleartext-keys=%v, no-cache=%v, allow-unknown-revocation=%v, sudo=%v, redact=%v, show-everything=%v\n",
			*version, *genkey, vanmoof.ScrubText(*generate), vanmoof.Redact(*cert), vanmoof.Redact(*pubkey), vanmoof.RedactID(*frameNumber), vanmoof.Redact(*email), bikesShown, vanmoof.ScrubText(*showKeys), *newKey, *showSaved, vanmoof.ScrubText(*invitations), *cleartextKeys, *noCache, *allowUnknownRevocation, *sudo, *redact, *showEverything)
	}

	if *version {
		fmt.Println("vanmoof-certificates version", vanmoof.Version)
		fmt.Printf("OS: %s, Arch: %s, Go: %s, CPUs: %d, Compiler: %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), runtime.Compiler)
		return 0
	}

	// Everything below handles secrets (keys, tokens, the password): keep them off disk
	hardenMemory(*debug)

	if genkey != nil && *genkey {
		privKeyB64, pubKeyB64, err := vanmoof.GenerateED25519()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return exitFailure
		}
		fmt.Printf("Privkey = %s\n", vanmoof.Redact(privKeyB64))
		fmt.Printf("Pubkey = %s\n", vanmoof.Redact(pubKeyB64))
		return 0
	}

	// Generate a self-signed certificate from a config file, needing no account or network
	if *generate != "" {
		if err := vanmoof.GenerateCert(*generate, *debug); err != nil {
			fmt.Printf("Error: %v\n", vanmoof.ScrubText(err.Error()))
			return exitFailure
		}
		return 0
	}

	// Validate show-keys if provided
	if *showKeys != "" {
		if *showKeys != vanmoof.ShowKeysStatic && *showKeys != vanmoof.ShowKeysAll {
			fmt.Printf("Error: Invalid -show-keys value '%s'. Must be '%s' or '%s'\n", vanmoof.ScrubText(*showKeys), vanmoof.ShowKeysStatic, vanmoof.ShowKeysAll)
			return exitUsage
		}
		if *cert != "" {
			fmt.Println("Error: -show-keys cannot be combined with -cert")
			return exitUsage
		}
	}

	if *newKey {
		if *pubkey != "" {
			fmt.Println("Error: -new-key and -pubkey cannot be combined")
			return exitUsage
		}
		if *cert != "" || *showKeys == vanmoof.ShowKeysStatic || *showSaved {
			fmt.Println("Error: -new-key only works when requesting certificates")
			return exitUsage
		}
	}
	invitationAction, invitationSelection, hasSelection := strings.Cut(*invitations, "=")
	if *invitations != "" {
		switch {
		case invitationAction != vanmoof.InvitationsList && invitationAction != vanmoof.InvitationsAccept && invitationAction != vanmoof.InvitationsDecline:
			fmt.Printf("Error: Invalid -invitations value '%s'. Must be '%s', '%s' or '%s'\n", vanmoof.ScrubText(*invitations), vanmoof.InvitationsList, vanmoof.InvitationsAccept, vanmoof.InvitationsDecline)
			return exitUsage
		case hasSelection && (invitationAction == vanmoof.InvitationsList || strings.TrimSpace(invitationSelection) == ""):
			fmt.Println("Error: -invitations takes the invitations after '=' only to accept or decline them, e.g. 'accept=all'")
			return exitUsage
		}
		if *cert != "" || *showKeys != "" || *showSaved || *pubkey != "" || *newKey {
			fmt.Println("Error: -invitations cannot be combined with -cert, -show-keys, -show-saved, -pubkey or -new-key")
			return exitUsage
		}
	}

	if *cleartextKeys && *noCache {
		fmt.Println("Error: -cleartext-keys and -no-cache cannot be combined")
		return exitUsage
	}
	if *showSaved && (*cert != "" || *showKeys != "" || *pubkey != "" || *noCache) {
		fmt.Println("Error: -show-saved cannot be combined with -cert, -show-keys, -pubkey or -no-cache")
		return exitUsage
	}

	// Validate cert if provided
	if *cert != "" {
		if !*sudo && !vanmoof.IsValidBase64(*cert) {
			fmt.Println("Error: Invalid base64 certificate string")
			return exitUsage
		}
	}

	// Validate pubkey if provided
	if *pubkey != "" {
		if !*sudo && !vanmoof.IsValidEd25519PublicKey(*pubkey) {
			fmt.Println("Error: Invalid Ed25519 public key. Must be base64-encoded 32 or 33 bytes")
			return exitUsage
		}
	}

	// Validate framenumber if provided
	if *frameNumber != "" {
		if *cert == "" {
			fmt.Println("Error: -framenumber only works with -cert (use -bikes to pick bikes)")
			return exitUsage
		}
		if !*sudo && !vanmoof.ValidateFrameNumber(*frameNumber) {
			fmt.Printf("Error: Invalid frame number '%s'\n", vanmoof.RedactID(*frameNumber))
			return exitUsage
		}
	}

	// Validate bikes parameter
	if *bikes != "all" && *bikes != "ask" {
		for id := range strings.SplitSeq(*bikes, ",") {
			id = strings.TrimSpace(id)
			if id == "" {
				fmt.Println("Error: Empty bike ID in bikes list")
				return exitUsage
			}
			if _, ok := vanmoof.ParseBikeID(id); !ok {
				// Any generation's frame number, not just SA5/S6: -show-keys picks older bikes
				if !*sudo && !vanmoof.LooksLikeFrameNumber(id) {
					fmt.Printf("Error: Invalid bike ID '%s' in bikes list. Must be a numeric ID or frame number\n", vanmoof.RedactID(id))
					return exitUsage
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
				return exitFailure
			}
		}

		if !*sudo && !vanmoof.IsValidEmail(emailInput) {
			fmt.Printf("Error: Invalid email address '%s'\n", vanmoof.Redact(emailInput))
			return exitUsage
		}

		if *showSaved {
			if err := vanmoof.ShowSaved(emailInput, *debug); err != nil {
				fmt.Printf("Error: %v\n", vanmoof.ScrubText(err.Error()))
				return exitFailure
			}
			return 0
		}

		opts := vanmoof.Options{BikeFilter: *bikes, PublicKey: *pubkey, NewKey: *newKey, Debug: *debug, NoCache: *noCache, CleartextKeys: *cleartextKeys}
		if *invitations != "" {
			if err := vanmoof.Invitations(emailInput, invitationAction, strings.TrimSpace(invitationSelection), opts); err != nil {
				fmt.Printf("Error: %v\n", vanmoof.ScrubText(err.Error()))
				return exitFailure
			}
			return 0
		}

		if *showKeys != "" {
			// ShowKeys itself requests certificates too in "all" mode, reusing the
			// authentication and customer data it already fetched for the keys.
			if err := vanmoof.ShowKeys(emailInput, *showKeys, opts); err != nil {
				fmt.Printf("Error: %v\n", vanmoof.ScrubText(err.Error()))
				return exitFailure
			}
			return 0
		}

		if err := vanmoof.GetCert(emailInput, opts); err != nil {
			fmt.Printf("Error: %v\n", vanmoof.ScrubText(err.Error()))
			return exitFailure
		}
		return 0
	}

	if !vanmoof.ProcessCertificate(*cert, *pubkey, *frameNumber, *debug) {
		return exitFailure
	}
	return 0
}

// escaped writes to w with control characters (but line breaks and tabs), bidi overrides
// and invalid UTF-8 escaped: the flag package quotes a mistyped flag as it is
type escaped struct{ w io.Writer }

func (e escaped) Write(p []byte) (int, error) {
	var b strings.Builder
	for _, r := range string(p) {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case unicode.IsControl(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		case unicode.Is(unicode.Bidi_Control, r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r) // invalid UTF-8 as U+FFFD
		}
	}
	if _, err := io.WriteString(e.w, b.String()); err != nil {
		return 0, err
	}
	return len(p), nil
}
