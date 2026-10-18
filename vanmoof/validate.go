package vanmoof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/mail"
	"regexp"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// IsValidEmail reports whether email is a bare email address, such as user@example.com:
// it's used as is to log in, so a display name, comment or spaces around it don't count.
func IsValidEmail(email string) bool {
	addr, err := mail.ParseAddress(email)
	return err == nil && addr.Address == email
}

// IsValidBase64 validates a base64 string
func IsValidBase64(s string) bool {
	if s == "" {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// IsValidEd25519PublicKey validates an Ed25519 public key
func IsValidEd25519PublicKey(pubkey string) bool {
	if pubkey == "" {
		return false
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		return false
	}

	// Ed25519 public keys are 32 bytes
	// Some implementations prefix with a 0x00 byte, making it 33 bytes
	if len(decoded) != ed25519.PublicKeySize && len(decoded) != ed25519.PublicKeySize+1 {
		return false
	}

	// If 33 bytes, check the first byte is 0x00
	if len(decoded) == ed25519.PublicKeySize+1 {
		if decoded[0] != 0x00 {
			return false
		}
	}

	return true
}

// ValidateFrameNumber validates a frame number against a pattern
func ValidateFrameNumber(frameNumber string) bool {
	if frameNumber == "" {
		return false
	}

	// Check against pattern
	matched, err := regexp.MatchString(frameNumberPattern, frameNumber)
	if err != nil {
		return false
	}

	return matched
}

// ParseBikeID parses s as a bike's numeric API ID. Only digits count: fmt.Sscanf would
// also read "123abc" as bike 123.
func ParseBikeID(s string) (int, bool) {
	id, err := strconv.ParseUint(s, 10, 31) // 31 bits fit an int everywhere
	return int(id), err == nil
}

// LooksLikeFrameNumber reports whether s could be a frame number of any generation, for
// picking bikes with -bikes. Unlike ValidateFrameNumber it accepts more than the SA5/S6
// formats, since an unknown one does no harm there: it just matches none of the bikes.
func LooksLikeFrameNumber(s string) bool {
	return anyFrameNumberRegexp.MatchString(s)
}

func validateAndShowJWT(tokenString string) {
	fmt.Println("\n[DEBUG] JWT Token Analysis:")

	// Parse without validation first to inspect the token
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})

	if err != nil {
		fmt.Printf("[DEBUG] Failed to parse JWT: %v\n", ScrubText(err.Error()))
		return
	}

	// Show header and claims/payload, which -redact hides apart from harmless fields
	header, _ := redactValue(token.Header, "", false)
	if headerJSON, err := json.MarshalIndent(header, "[DEBUG]   ", "  "); err == nil {
		fmt.Printf("[DEBUG] JWT Header:\n%s\n", printableLines(string(headerJSON)))
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		payload, _ := redactValue(map[string]any(claims), "", false)
		if claimsJSON, err := json.MarshalIndent(payload, "[DEBUG]   ", "  "); err == nil {
			fmt.Printf("[DEBUG] JWT Payload:\n%s\n", printableLines(string(claimsJSON)))
		}
	}

	// Show signature info: the signature is what makes the token usable, so it's a secret
	parts := strings.Split(tokenString, ".")
	if len(parts) == 3 {
		fmt.Printf("[DEBUG] JWT Signature (base64): %s\n", debugSecret(parts[2][:min(40, len(parts[2]))]+"..."))
	}

	fmt.Println()
}

// knownCAKeys are VanMoof's certificate signing (CA) public keys.
// Format: hex-encoded 32-byte Ed25519 public key.
var knownCAKeys = []string{
	// BLE certificate signing key recovered from the bike; verifies the
	// Ed25519 signature embedded in every certificate.
	"29b1f31c07d1c63b124057ebe75a0bc0796259722e5dd9a9a9302ae2061184a0",
}

// verifyCertificateSignature reports whether the signature verifies against any
// known CA key. hasKeys is false when no CA keys are configured.
func verifyCertificateSignature(signature, payload []byte) (verified, hasKeys bool) {
	if len(knownCAKeys) == 0 {
		return false, false
	}
	for _, keyHex := range knownCAKeys {
		pubKeyBytes, err := hex.DecodeString(keyHex)
		if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pubKeyBytes), payload, signature) {
			return true, true
		}
	}
	return false, true
}

// validateCertificateSignature prints detailed signature validation (debug mode)
func validateCertificateSignature(signature, payload []byte, debug, perBikeKey bool) {
	if !debug {
		return // Only show in debug mode
	}

	fmt.Println("\n[DEBUG] Signature Validation:")

	if len(knownCAKeys) == 0 {
		fmt.Println("  ⚠ No VanMoof CA public keys available for validation")
		fmt.Println("  The signature appears to be a valid Ed25519 signature (64 bytes)")
		fmt.Println("  To validate, we would need VanMoof's Certificate Authority public key")
		return
	}

	// Try each known CA public key
	validated := false
	for i, keyHex := range knownCAKeys {
		pubKeyBytes, err := hex.DecodeString(keyHex)
		if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
			fmt.Printf("  ✗ CA key %d: Invalid format\n", i+1)
			continue
		}

		pubKey := ed25519.PublicKey(pubKeyBytes)
		if ed25519.Verify(pubKey, payload, signature) {
			fmt.Printf("  ✓ Signature VALID with CA key %d\n", i+1)
			fmt.Printf("    CA Public Key: %x\n", pubKeyBytes)
			validated = true
			break
		}
	}

	if !validated && len(knownCAKeys) > 0 {
		if perBikeKey {
			fmt.Println("  Info: Signature verification unavailable for S6 (no signing key known yet)")
			return
		}
		fmt.Println("  ✗ Signature validation failed with all known CA keys")
	}
}

// validateUUID validates that the byte array is a valid UUID
func validateUUID(uuid []byte) bool {
	if len(uuid) != 16 {
		return false
	}

	// Check version field (byte 6, high nibble should be 1-8, the versions of RFC 9562)
	version := uuid[6] >> 4
	if version < 1 || version > 8 {
		return false
	}

	// Check variant field (byte 8, high 2 bits should be 10)
	variant := uuid[8] >> 6
	return variant == 0b10
}
