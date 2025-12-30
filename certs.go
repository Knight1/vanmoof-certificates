package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// CertificatePayload represents the CBOR-encoded certificate structure
type CertificatePayload struct {
	ID        uint32                 `cbor:"i"`  // Bike API ID
	FrameID   []byte                 `cbor:"fm"` // Frame module serial (byte string)
	BikeID    []byte                 `cbor:"bm"` // Bike module serial (byte string)
	Expiry    uint32                 `cbor:"e"`  // Expiry timestamp
	Role      uint8                  `cbor:"r"`  // Access level/role
	UserID    []byte                 `cbor:"u"`  // User ID (16 bytes)
	PublicKey []byte                 `cbor:"p"`  // Public key (32 bytes)
	Extra     map[string]interface{} `cbor:",inline"`
}

func processCertificate(certStr, expectedPubKeyStr, bikeID, expectedUserID string, bikes []BikeData, debug bool) {

	// Check if certificate is empty
	if certStr == "" {
		fmt.Println("Error: Certificate string is empty")
		return
	}

	// Decode the certificate
	certData, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		fmt.Println("Error decoding certificate:", err)
		return
	}

	fmt.Printf("Total Certificate Length: %d bytes\n", len(certData))
	if debug {
		fmt.Printf("Decoded Certificate (hex): %x\n", certData)
	}

	// Check if certificate has minimum length
	if len(certData) < 134 {
		fmt.Println("Error: Certificate is too short")
		return
	}

	// --- Extract Components ---

	// The Signature (First 64 bytes)
	signature := certData[0:64]

	// The CBOR Payload starts at byte 64
	cborPayload := certData[64:]

	// --- Display Extracted Information ---

	// Display signature
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	fmt.Printf("\n--- Extracted from Certificate ---\n")
	fmt.Printf("Signature (Base64): %s\n", signatureBase64)
	if debug {
		fmt.Printf("Signature (hex): %x\n", signature)
		fmt.Printf("CBOR Payload length: %d bytes\n", len(cborPayload))
		fmt.Printf("CBOR Payload (hex): %x\n", cborPayload)

		// Parse signature structure
		fmt.Println("\n[DEBUG] Signature Analysis:")
		fmt.Printf("  Signature is %d bytes (Ed25519 signature)\n", len(signature))
		fmt.Printf("  R component (first 32 bytes): %x\n", signature[:32])
		fmt.Printf("  S component (last 32 bytes):  %x\n", signature[32:])
	}

	// Try to validate signature if VanMoof CA public key is available
	validateCertificateSignature(signature, cborPayload, debug)

	// Parse CBOR payload - first try as a raw map to see all fields
	var rawMap map[interface{}]interface{}
	err = cbor.Unmarshal(cborPayload, &rawMap)
	if err != nil {
		fmt.Println("Error parsing CBOR payload:", err)
		return
	}

	if debug {
		fmt.Printf("Debug - Raw CBOR map: %+v\n", rawMap)
	}

	// --- Validate Certificate Structure ---
	fmt.Println("\n--- Certificate Validation ---")
	validationErrors := 0
	validationWarnings := 0

	// Check for required CBOR fields
	requiredFields := []string{"i", "f", "b", "e", "r", "u", "p"}
	for _, field := range requiredFields {
		if _, exists := rawMap[field]; !exists {
			fmt.Printf("✗ Missing required field: '%s'\n", field)
			validationErrors++
		}
	}

	// Extract fields from raw map
	var apiID uint32
	var frameID, bikeIDBytes, userID, publicKey []byte
	var expiry uint32
	var role uint8

	for key, value := range rawMap {
		keyStr, ok := key.(string)
		if !ok {
			continue
		}
		switch keyStr {
		case "i":
			if v, ok := value.(uint64); ok {
				apiID = uint32(v)
			} else {
				fmt.Printf("✗ Field 'i' has incorrect type (expected uint)\n")
				validationErrors++
			}
		case "f": // Frame ID (was "fm")
			if v, ok := value.(string); ok {
				frameID = []byte(v)
			} else {
				fmt.Printf("✗ Field 'f' has incorrect type (expected string)\n")
				validationErrors++
			}
		case "b": // Bike ID (was "bm")
			if v, ok := value.(string); ok {
				bikeIDBytes = []byte(v)
			} else {
				fmt.Printf("✗ Field 'b' has incorrect type (expected string)\n")
				validationErrors++
			}
		case "e":
			if v, ok := value.(uint64); ok {
				expiry = uint32(v)
			} else {
				fmt.Printf("✗ Field 'e' has incorrect type (expected uint)\n")
				validationErrors++
			}
		case "r":
			if v, ok := value.(uint64); ok {
				role = uint8(v)
			} else {
				fmt.Printf("✗ Field 'r' has incorrect type (expected uint)\n")
				validationErrors++
			}
		case "u":
			userID, ok = value.([]byte)
			if !ok {
				fmt.Printf("✗ Field 'u' has incorrect type (expected bytes)\n")
				validationErrors++
			} else if len(userID) != 16 {
				fmt.Printf("✗ Field 'u' has incorrect length (expected 16 bytes, got %d)\n", len(userID))
				validationErrors++
			}
		case "p":
			publicKey, ok = value.([]byte)
			if !ok {
				fmt.Printf("✗ Field 'p' has incorrect type (expected bytes)\n")
				validationErrors++
			} else if len(publicKey) != 32 {
				fmt.Printf("✗ Field 'p' has incorrect length (expected 32 bytes, got %d)\n", len(publicKey))
				validationErrors++
			}
		default:
			if debug {
				fmt.Printf("[DEBUG] Unknown field in certificate: '%s'\n", keyStr)
			}
		}
	}

	// Validate field contents
	if len(frameID) == 0 {
		fmt.Printf("✗ Frame ID (f) is empty\n")
		validationErrors++
	} else if !validateFrameNumber(string(frameID)) {
		fmt.Printf("⚠ Frame ID (f) has invalid format: %s\n", string(frameID))
		validationWarnings++
	}

	if len(bikeIDBytes) == 0 {
		fmt.Printf("✗ Bike ID (b) is empty\n")
		validationErrors++
	} else if !validateFrameNumber(string(bikeIDBytes)) {
		fmt.Printf("⚠ Bike ID (b) has invalid format: %s\n", string(bikeIDBytes))
		validationWarnings++
	}

	// Validate expiry
	now := time.Now().Unix()
	if expiry == 0 {
		fmt.Printf("✗ Expiry timestamp is zero\n")
		validationErrors++
	} else if int64(expiry) < now {
		fmt.Printf("✗ Certificate has EXPIRED (expired %s ago)\n", time.Since(time.Unix(int64(expiry), 0)).Round(time.Second))
		validationErrors++
	} else if int64(expiry) > now+365*24*60*60 {
		fmt.Printf("⚠ Certificate expiry is suspiciously far in the future (%.1f days)\n", float64(int64(expiry)-now)/86400)
		validationWarnings++
	}

	// Validate role
	validRoles := []uint8{0x00, 0x01, 0x03, 0x07, 0x0F}
	roleValid := false
	for _, validRole := range validRoles {
		if role == validRole {
			roleValid = true
			break
		}
	}
	if !roleValid {
		fmt.Printf("⚠ Unknown role value: 0x%02X\n", role)
		validationWarnings++
	}

	// Validate UUID
	if len(userID) == 16 {
		if !validateUUID(userID) {
			fmt.Printf("⚠ User UUID has invalid version or variant\n")
			validationWarnings++
		}
	}

	// Display validation summary
	if validationErrors == 0 && validationWarnings == 0 {
		fmt.Printf("✓ Certificate structure is valid\n")
	} else {
		if validationErrors > 0 {
			fmt.Printf("✗ Certificate has %d error(s)\n", validationErrors)
		}
		if validationWarnings > 0 {
			fmt.Printf("⚠ Certificate has %d warning(s)\n", validationWarnings)
		}
	}

	// Display parsed fields
	// Note: The 'i' field changes with each certificate and is not the bike's API ID
	fmt.Printf("Certificate ID: %d\n", apiID)

	// Display and validate Frame Module serial
	frameIDStr := string(frameID)
	fmt.Printf("AFM (Authorized Frame Module): %s", frameIDStr)

	// Check if frame module serial matches API bikes
	frameModuleValid := false
	if frameIDStr != "" {
		if validateFrameNumber(frameIDStr) {
			if len(bikes) > 0 {
				for _, bike := range bikes {
					if bike.FrameNumber == frameIDStr || bike.FrameSerial == frameIDStr {
						frameModuleValid = true
						break
					}
				}
				if frameModuleValid {
					fmt.Printf(" ✓ Valid (matches API bike)\n")
				} else {
					fmt.Printf(" ✓ Valid format, ⚠ not found in API bikes\n")
				}
			} else {
				fmt.Printf(" ✓ Valid format\n")
			}
		} else {
			fmt.Printf(" ✗ Invalid format\n")
		}
	} else {
		fmt.Println()
	}

	// Display and validate Bike Module serial
	bikeIDStr := string(bikeIDBytes)
	fmt.Printf("ABM (Authorized Bike Module): %s", bikeIDStr)

	// Check if bike module serial matches API bikes
	bikeModuleValid := false
	if bikeIDStr != "" {
		if validateFrameNumber(bikeIDStr) {
			if len(bikes) > 0 {
				for _, bike := range bikes {
					if bike.FrameNumber == bikeIDStr || bike.FrameSerial == bikeIDStr || bike.MainEcuSerial == bikeIDStr {
						bikeModuleValid = true
						break
					}
				}
				if bikeModuleValid {
					fmt.Printf(" ✓ Valid (matches API bike)\n")
				} else {
					fmt.Printf(" ✓ Valid format, ⚠ not found in API bikes\n")
				}
			} else {
				fmt.Printf(" ✓ Valid format\n")
			}
		} else {
			fmt.Printf(" ✗ Invalid format\n")
		}
	} else {
		fmt.Println()
	}

	// Convert and display expiry timestamp
	expiryTime := time.Unix(int64(expiry), 0)
	fmt.Printf("Certificate Expiry: %s (Unix: %d)\n", expiryTime.Format("2006-01-02 15:04:05 MST"), expiry)

	// Display access level
	accessLevel := getRoleDescription(role)
	fmt.Printf("Access Level: %s\n", accessLevel)

	// Display and validate user ID
	userUUIDStr := formatUUID(userID)
	fmt.Printf("User ID: %s", userUUIDStr)
	if validateUUID(userID) {
		fmt.Printf(" ✓ Valid UUID v%d\n", getUUIDVersion(userID))
	} else {
		fmt.Printf(" ✗ Invalid UUID\n")
	}

	// Display embedded public key
	embeddedPubKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)
	fmt.Printf("Embedded Public Key (Base64): %s\n", embeddedPubKeyBase64)

	// --- Certificate Validation Summary ---
	if len(bikes) > 0 {
		fmt.Println("\n--- Certificate Validation Summary ---")

		// Check if certificate matches any bike from API based on frame/bike serials
		var matchedBike *BikeData
		for i, bike := range bikes {
			// Match by frame number or serial
			if (frameIDStr != "" && (bike.FrameNumber == frameIDStr || bike.FrameSerial == frameIDStr)) ||
				(bikeIDStr != "" && (bike.FrameNumber == bikeIDStr || bike.FrameSerial == bikeIDStr || bike.MainEcuSerial == bikeIDStr)) {
				matchedBike = &bikes[i]
				break
			}
		}

		if matchedBike != nil {
			fmt.Printf("✓ Certificate is VALID for your bike\n")
			fmt.Printf("  Matched Bike ID: %d\n", matchedBike.BikeID)
			fmt.Printf("  Bike Name: %s\n", matchedBike.Name)
			fmt.Printf("  Frame Number: %s\n", matchedBike.FrameNumber)
		} else {
			fmt.Printf("✗ Certificate does NOT match any of your bikes\n")
			fmt.Printf("  Certificate AFM: %s\n", frameIDStr)
			fmt.Printf("  Certificate ABM: %s\n", bikeIDStr)
			fmt.Printf("  Your bikes: ")
			for i, bike := range bikes {
				if i > 0 {
					fmt.Printf(", ")
				}
				fmt.Printf("%s (ID: %d)", bike.FrameNumber, bike.BikeID)
			}
			fmt.Println()
		}
	}

	// --- Parse Certificate Fields ---

	// --- Verification Logic ---

	if bikeID != "" {
		fmt.Println("\n--- Bike ID Verification ---")
		// Try to match as frame number (string)
		frameIDStr := string(frameID)
		bikeIDStr := string(bikeIDBytes)

		// Check if bikeID is numeric (API bike ID) or string (frame number)
		var parsedNumericID uint32
		isNumeric := false
		if _, err := fmt.Sscanf(bikeID, "%d", &parsedNumericID); err == nil {
			isNumeric = true
		} else {
			// Not a number, so should be a frame number - validate format
			if !validateFrameNumber(bikeID) {
				fmt.Printf("⚠ Warning: Bike ID '%s' has invalid frame number format\n", bikeID)
			}
		}

		// If we have bikes from API and a numeric ID was provided, check against API bikes
		var matchedBike *BikeData
		if isNumeric && len(bikes) > 0 {
			for i, bike := range bikes {
				if bike.BikeID == int(parsedNumericID) {
					matchedBike = &bikes[i]
					break
				}
			}

			if matchedBike != nil {
				// Found bike in API, now verify certificate matches this bike
				if (frameIDStr == matchedBike.FrameNumber || frameIDStr == matchedBike.FrameSerial) &&
					(bikeIDStr == matchedBike.FrameNumber || bikeIDStr == matchedBike.FrameSerial || bikeIDStr == matchedBike.MainEcuSerial) {
					fmt.Printf("✓ Bike ID Verified: %d (%s)\n", matchedBike.BikeID, matchedBike.FrameNumber)
					fmt.Printf("  Certificate matches bike from your account\n")
				} else {
					fmt.Printf("✗ Bike ID mismatch\n")
					fmt.Printf("  API Bike %d has frame: %s\n", matchedBike.BikeID, matchedBike.FrameNumber)
					fmt.Printf("  Certificate has AFM: %s, ABM: %s\n", frameIDStr, bikeIDStr)
				}
			} else {
				fmt.Printf("✗ Bike ID %d not found in your account\n", parsedNumericID)
				if len(bikes) > 0 {
					fmt.Printf("  Your bike IDs: ")
					for i, bike := range bikes {
						if i > 0 {
							fmt.Printf(", ")
						}
						fmt.Printf("%d", bike.BikeID)
					}
					fmt.Println()
				}
			}
		} else if !isNumeric {
			// Frame number provided, match directly against certificate
			if frameIDStr == bikeID || bikeIDStr == bikeID {
				fmt.Println("✓ Bike ID Verified (Frame Number):", bikeID)
			} else {
				fmt.Printf("✗ Bike ID NOT found: %s (Certificate Frame: %s, Bike: %s)\n", bikeID, frameIDStr, bikeIDStr)
			}
		} else {
			// Numeric ID but no bikes to verify against
			fmt.Printf("⚠ Cannot verify numeric bike ID %d (no API bikes available)\n", parsedNumericID)
		}
	}

	if expectedPubKeyStr != "" {
		fmt.Println("\n--- Public Key Verification ---")
		// Decode the provided public key
		pubKeyData, err := base64.StdEncoding.DecodeString(expectedPubKeyStr)
		if err != nil {
			fmt.Println("Error decoding public key:", err)
			return
		}
		// Note: The Public Key string has a leading 0x00 byte (prefix)
		// We compare the last 32 bytes of your key to the embedded key
		if bytes.Equal(publicKey, pubKeyData[len(pubKeyData)-32:]) {
			fmt.Println("✓ Success: Public Key matches the Certificate signature.")
		} else {
			fmt.Println("✗ Warning: Key mismatch detected.")
		}
	}

	if expectedUserID != "" {
		fmt.Println("\n--- User ID Verification ---")
		// Convert certificate user ID from bytes to UUID format
		certUserID := fmt.Sprintf("%x", userID)
		// Remove hyphens from expected UUID for comparison
		expectedUserIDClean := ""
		for _, c := range expectedUserID {
			if c != '-' {
				expectedUserIDClean += string(c)
			}
		}

		if certUserID == expectedUserIDClean {
			fmt.Printf("✓ User ID Verified: %s\n", expectedUserID)
		} else {
			fmt.Printf("✗ User ID mismatch\n")
			fmt.Printf("  Expected: %s\n", expectedUserID)
			fmt.Printf("  Certificate: %s\n", certUserID)
		}
	}
}

// getRoleDescription returns a human-readable description of the role value
func getRoleDescription(role uint8) string {
	switch role {
	case 0x00:
		return "Guest (Read-Only Access)"
	case 0x01:
		return "Limited Access"
	case 0x03:
		return "Owner (Standard Access)"
	case 0x07:
		return "Owner (Full Control)"
	case 0x0F:
		return "Service/Admin (Extended Permissions)"
	default:
		return fmt.Sprintf("Unknown Role (0x%02X)", role)
	}
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

// formatUUID formats a 16-byte UUID into standard hyphenated format
func formatUUID(uuid []byte) string {
	if len(uuid) != 16 {
		return fmt.Sprintf("%x", uuid)
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// getUUIDVersion extracts the version number from a UUID
func getUUIDVersion(uuid []byte) int {
	if len(uuid) != 16 {
		return 0
	}
	// Version is in the high nibble of byte 6
	return int(uuid[6] >> 4)
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
