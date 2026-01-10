package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

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

// isValidEd25519PublicKey validates an Ed25519 public key
func isValidEd25519PublicKey(pubkey string) bool {
	pubkey = strings.TrimSpace(pubkey)
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

func validateAndShowJWT(tokenString string) {
	fmt.Println("\n[DEBUG] JWT Token Analysis:")

	// Parse without validation first to inspect the token
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})

	if err != nil {
		fmt.Printf("[DEBUG] Failed to parse JWT: %v\n", err)
		return
	}

	// Show header
	if headerJSON, err := json.MarshalIndent(token.Header, "[DEBUG]   ", "  "); err == nil {
		fmt.Printf("[DEBUG] JWT Header:\n%s\n", string(headerJSON))
	}

	// Show claims/payload
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if claimsJSON, err := json.MarshalIndent(claims, "[DEBUG]   ", "  "); err == nil {
			fmt.Printf("[DEBUG] JWT Payload:\n%s\n", string(claimsJSON))
		}
	}

	// Show signature info
	parts := strings.Split(tokenString, ".")
	if len(parts) == 3 {
		fmt.Printf("[DEBUG] JWT Signature (base64): %s...\n", parts[2][:min(40, len(parts[2]))])
	}

	fmt.Println()
}

// validateCertificateSignature attempts to validate the Ed25519 signature
func validateCertificateSignature(signature, payload []byte, debug bool) {
	// Known VanMoof CA public keys = none

	knownCAKeys := []string{
		// Add known VanMoof CA public keys here when discovered
		// Format: hex-encoded 32-byte Ed25519 public key
	}

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
		fmt.Println("  ✗ Signature validation failed with all known CA keys")
	}
}

// validateUUID validates that the byte array is a valid UUID
func validateUUID(uuid []byte) bool {
	if len(uuid) != 16 {
		return false
	}

	// Check version field (byte 6, high nibble should be 1-5)
	version := uuid[6] >> 4
	if version < 1 || version > 5 {
		return false
	}

	// Check variant field (byte 8, high 2 bits should be 10)
	variant := uuid[8] >> 6
	return variant == 0b10
}

// validateFrameNumber validates a frame number against a pattern
func validateFrameNumber(frameNumber string) bool {
	if frameNumber == "" {
		return false
	}

	// Check against pattern
	matched, err := regexp.MatchString(FrameNumberPattern, frameNumber)
	if err != nil {
		return false
	}

	if matched {
		return true
	}

	return false
}
