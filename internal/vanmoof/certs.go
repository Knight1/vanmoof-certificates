package vanmoof

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func ProcessCertificate(certStr, expectedPubKeyStr, bikeID, expectedUserID string, bikes []BikeData, debug bool) {
	if certStr == "" {
		fmt.Println("Error: Certificate string is empty")
		return
	}

	certData, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		fmt.Println("Error decoding certificate:", err)
		return
	}

	if len(certData) < 134 {
		fmt.Println("Error: Certificate is too short")
		return
	}

	// Parse certificate into result struct
	r := parseCertificate(certData, bikes)

	// Cross-reference verifications
	verifyBikeID(&r, bikeID, bikes)
	verifyPublicKey(&r, expectedPubKeyStr)
	verifyUserID(&r, expectedUserID)

	// Output
	if debug {
		printVerbose(r, certData, expectedPubKeyStr, bikeID, expectedUserID, bikes)
		validateCertificateSignature(r.signature, certData[64:], debug)
	} else {
		printCompact(r)
	}
}

// parseCertificate extracts and validates all fields from raw certificate bytes
func parseCertificate(certData []byte, bikes []BikeData) certResult {
	r := certResult{
		signature: certData[0:64],
	}

	cborPayload := certData[64:]

	var rawMap map[interface{}]interface{}
	if err := cbor.Unmarshal(cborPayload, &rawMap); err != nil {
		r.errors = append(r.errors, fmt.Sprintf("CBOR parse error: %v", err))
		return r
	}

	// Check required fields
	for _, field := range []string{"i", "f", "b", "e", "r", "u", "p"} {
		if _, exists := rawMap[field]; !exists {
			r.errors = append(r.errors, fmt.Sprintf("Missing required field: '%s'", field))
		}
	}

	// Extract fields
	for key, value := range rawMap {
		keyStr, ok := key.(string)
		if !ok {
			continue
		}
		switch keyStr {
		case "i":
			if v, ok := value.(uint64); ok {
				r.apiID = uint32(v)
			} else {
				r.errors = append(r.errors, "Field 'i' has incorrect type (expected uint)")
			}
		case "f":
			if v, ok := value.(string); ok {
				r.frameID = []byte(v)
			} else {
				r.errors = append(r.errors, "Field 'f' has incorrect type (expected string)")
			}
		case "b":
			if v, ok := value.(string); ok {
				r.bikeID = []byte(v)
			} else {
				r.errors = append(r.errors, "Field 'b' has incorrect type (expected string)")
			}
		case "e":
			if v, ok := value.(uint64); ok {
				r.expiry = uint32(v)
			} else {
				r.errors = append(r.errors, "Field 'e' has incorrect type (expected uint)")
			}
		case "r":
			if v, ok := value.(uint64); ok {
				r.role = uint8(v)
			} else {
				r.errors = append(r.errors, "Field 'r' has incorrect type (expected uint)")
			}
		case "u":
			if v, ok := value.([]byte); ok {
				r.userID = v
				if len(v) != 16 {
					r.errors = append(r.errors, fmt.Sprintf("Field 'u' has incorrect length (expected 16 bytes, got %d)", len(v)))
				}
			} else {
				r.errors = append(r.errors, "Field 'u' has incorrect type (expected bytes)")
			}
		case "p":
			if v, ok := value.([]byte); ok {
				r.publicKey = v
				if len(v) != 32 {
					r.errors = append(r.errors, fmt.Sprintf("Field 'p' has incorrect length (expected 32 bytes, got %d)", len(v)))
				}
			} else {
				r.errors = append(r.errors, "Field 'p' has incorrect type (expected bytes)")
			}
		}
	}

	// Validate frame ID format
	if len(r.frameID) == 0 {
		r.errors = append(r.errors, "Frame ID (f) is empty")
	} else if !ValidateFrameNumber(string(r.frameID)) {
		r.warnings = append(r.warnings, fmt.Sprintf("Frame ID (f) has invalid format: %s", string(r.frameID)))
	}

	// Validate bike ID format
	if len(r.bikeID) == 0 {
		r.errors = append(r.errors, "Bike ID (b) is empty")
	} else if !ValidateFrameNumber(string(r.bikeID)) {
		r.warnings = append(r.warnings, fmt.Sprintf("Bike ID (b) has invalid format: %s", string(r.bikeID)))
	}

	// Validate expiry
	now := time.Now().Unix()
	if r.expiry == 0 {
		r.errors = append(r.errors, "Expiry timestamp is zero")
	} else if int64(r.expiry) < now {
		r.errors = append(r.errors, fmt.Sprintf("Certificate has EXPIRED (expired %s ago)", time.Since(time.Unix(int64(r.expiry), 0)).Round(time.Second)))
	} else if int64(r.expiry) > now+365*24*60*60 {
		r.warnings = append(r.warnings, fmt.Sprintf("Certificate expiry is suspiciously far in the future (%.1f days)", float64(int64(r.expiry)-now)/86400))
	}

	// Validate role
	validRoles := []uint8{0x00, 0x01, 0x03, 0x07, 0x0F, 0x0B}
	roleValid := false
	for _, validRole := range validRoles {
		if r.role == validRole {
			roleValid = true
			break
		}
	}
	if !roleValid {
		r.warnings = append(r.warnings, fmt.Sprintf("Unknown role value: 0x%02X", r.role))
	}

	// Validate UUID
	if len(r.userID) == 16 && !validateUUID(r.userID) {
		r.warnings = append(r.warnings, "User UUID has invalid version or variant")
	}

	// Match against API bikes
	frameIDStr := string(r.frameID)
	bikeIDStr := string(r.bikeID)
	for i, bike := range bikes {
		if (frameIDStr != "" && (bike.FrameNumber == frameIDStr || bike.FrameSerial == frameIDStr)) ||
			(bikeIDStr != "" && (bike.FrameNumber == bikeIDStr || bike.FrameSerial == bikeIDStr || bike.MainEcuSerial == bikeIDStr)) {
			r.matchedBike = &bikes[i]
			break
		}
	}

	return r
}

// verifyBikeID checks the certificate against the expected bike ID
func verifyBikeID(r *certResult, bikeID string, bikes []BikeData) {
	if bikeID == "" {
		return
	}

	frameIDStr := string(r.frameID)
	bikeIDStr := string(r.bikeID)

	var parsedNumericID uint32
	isNumeric := false
	if _, err := fmt.Sscanf(bikeID, "%d", &parsedNumericID); err == nil {
		isNumeric = true
	}

	if isNumeric && len(bikes) > 0 {
		for _, bike := range bikes {
			if bike.BikeID == int(parsedNumericID) {
				if (frameIDStr == bike.FrameNumber || frameIDStr == bike.FrameSerial) &&
					(bikeIDStr == bike.FrameNumber || bikeIDStr == bike.FrameSerial || bikeIDStr == bike.MainEcuSerial) {
					r.bikeIDVerified = true
				}
				return
			}
		}
		r.errors = append(r.errors, fmt.Sprintf("Bike ID %d not found in your account", parsedNumericID))
	} else if !isNumeric {
		if frameIDStr == bikeID || bikeIDStr == bikeID {
			r.bikeIDVerified = true
		} else {
			r.errors = append(r.errors, fmt.Sprintf("Bike frame %s not found in certificate (AFM: %s, ABM: %s)", bikeID, frameIDStr, bikeIDStr))
		}
	}
}

// verifyPublicKey checks the embedded public key against the expected key
func verifyPublicKey(r *certResult, expectedPubKeyStr string) {
	if expectedPubKeyStr == "" {
		return
	}
	pubKeyData, err := base64.StdEncoding.DecodeString(expectedPubKeyStr)
	if err != nil {
		r.errors = append(r.errors, "Error decoding expected public key")
		return
	}
	if bytes.Equal(r.publicKey, pubKeyData[len(pubKeyData)-32:]) {
		r.pubKeyVerified = true
	} else {
		r.errors = append(r.errors, "Public key mismatch: certificate key does not match provided key")
	}
}

// verifyUserID checks the certificate user ID against the expected UUID
func verifyUserID(r *certResult, expectedUserID string) {
	if expectedUserID == "" {
		return
	}
	certUserID := fmt.Sprintf("%x", r.userID)
	expectedClean := strings.ReplaceAll(expectedUserID, "-", "")
	if certUserID == expectedClean {
		r.userIDVerified = true
	} else {
		r.errors = append(r.errors, fmt.Sprintf("User ID mismatch: expected %s, certificate has %s", expectedUserID, certUserID))
	}
}

// printCompact prints a one-line summary (normal mode)
func printCompact(r certResult) {
	frameIDStr := string(r.frameID)
	expiryTime := time.Unix(int64(r.expiry), 0)
	accessLevel := getRoleDescription(r.role)

	if len(r.errors) == 0 {
		parts := []string{frameIDStr, accessLevel, "expires " + expiryTime.Format("2006-01-02 15:04:05 MST")}
		if r.matchedBike != nil {
			parts = append(parts, "bike matched")
		}
		if r.pubKeyVerified {
			parts = append(parts, "pubkey ok")
		}
		if r.userIDVerified {
			parts = append(parts, "user ok")
		}
		fmt.Printf("Certificate valid: %s\n", strings.Join(parts, ", "))
	} else {
		fmt.Printf("Certificate INVALID: %d error(s), %d warning(s)\n", len(r.errors), len(r.warnings))
		for _, e := range r.errors {
			fmt.Printf("  ✗ %s\n", e)
		}
		for _, w := range r.warnings {
			fmt.Printf("  ⚠ %s\n", w)
		}
	}
}

// printVerbose prints the full detailed output (debug mode)
func printVerbose(r certResult, certData []byte, expectedPubKeyStr, bikeID, expectedUserID string, bikes []BikeData) {
	fmt.Printf("Total Certificate Length: %d bytes\n", len(certData))
	fmt.Printf("Decoded Certificate (hex): %x\n", certData)

	signature := certData[0:64]
	cborPayload := certData[64:]

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	fmt.Printf("\n--- Extracted from Certificate ---\n")
	fmt.Printf("Signature (Base64): %s\n", signatureBase64)
	fmt.Printf("Signature (hex): %x\n", signature)
	fmt.Printf("CBOR Payload length: %d bytes\n", len(cborPayload))
	fmt.Printf("CBOR Payload (hex): %x\n", cborPayload)

	fmt.Println("\n[DEBUG] Signature Analysis:")
	fmt.Printf("  Signature is %d bytes (Ed25519 signature)\n", len(signature))
	fmt.Printf("  R component (first 32 bytes): %x\n", signature[:32])
	fmt.Printf("  S component (last 32 bytes):  %x\n", signature[32:])

	// Validation summary
	fmt.Println("\n--- Certificate Validation ---")
	if len(r.errors) == 0 && len(r.warnings) == 0 {
		fmt.Printf("✓ Certificate structure is valid\n")
	} else {
		for _, e := range r.errors {
			fmt.Printf("✗ %s\n", e)
		}
		for _, w := range r.warnings {
			fmt.Printf("⚠ %s\n", w)
		}
	}

	// Parsed fields
	fmt.Printf("Certificate ID: %d\n", r.apiID)

	frameIDStr := string(r.frameID)
	fmt.Printf("AFM (Authorized Frame Module): %s", frameIDStr)
	if r.matchedBike != nil && (r.matchedBike.FrameNumber == frameIDStr || r.matchedBike.FrameSerial == frameIDStr) {
		fmt.Printf(" ✓ Valid (matches API bike)\n")
	} else if ValidateFrameNumber(frameIDStr) {
		fmt.Printf(" ✓ Valid format\n")
	} else if frameIDStr != "" {
		fmt.Printf(" ✗ Invalid format\n")
	} else {
		fmt.Println()
	}

	bikeIDStr := string(r.bikeID)
	fmt.Printf("ABM (Authorized Bike Module): %s", bikeIDStr)
	if r.matchedBike != nil && (r.matchedBike.FrameNumber == bikeIDStr || r.matchedBike.FrameSerial == bikeIDStr || r.matchedBike.MainEcuSerial == bikeIDStr) {
		fmt.Printf(" ✓ Valid (matches API bike)\n")
	} else if ValidateFrameNumber(bikeIDStr) {
		fmt.Printf(" ✓ Valid format\n")
	} else if bikeIDStr != "" {
		fmt.Printf(" ✗ Invalid format\n")
	} else {
		fmt.Println()
	}

	expiryTime := time.Unix(int64(r.expiry), 0)
	fmt.Printf("Certificate Expiry: %s (Unix: %d)\n", expiryTime.Format("2006-01-02 15:04:05 MST"), r.expiry)
	fmt.Printf("Access Level: %s\n", getRoleDescription(r.role))

	userUUIDStr := formatUUID(r.userID)
	fmt.Printf("User ID: %s", userUUIDStr)
	if validateUUID(r.userID) {
		fmt.Printf(" ✓ Valid UUID v%d\n", getUUIDVersion(r.userID))
	} else {
		fmt.Printf(" ✗ Invalid UUID\n")
	}

	embeddedPubKeyBase64 := base64.StdEncoding.EncodeToString(r.publicKey)
	fmt.Printf("Embedded Public Key (Base64): %s\n", embeddedPubKeyBase64)

	// Bike match summary
	if len(bikes) > 0 {
		fmt.Println("\n--- Certificate Validation Summary ---")
		if r.matchedBike != nil {
			fmt.Printf("✓ Certificate is VALID for your bike\n")
			if r.matchedBike.BikeID != 0 {
				fmt.Printf("  Matched Bike ID: %d\n", r.matchedBike.BikeID)
			}
			fmt.Printf("  Bike Name: %s\n", r.matchedBike.Name)
			fmt.Printf("  Frame Number: %s\n", r.matchedBike.FrameNumber)
		} else {
			fmt.Printf("✗ Certificate does NOT match any of your bikes\n")
			fmt.Printf("  Certificate AFM: %s\n", frameIDStr)
			fmt.Printf("  Certificate ABM: %s\n", bikeIDStr)
			fmt.Printf("  Your bikes: ")
			for i, bike := range bikes {
				if i > 0 {
					fmt.Printf(", ")
				}
				if bike.BikeID != 0 {
					fmt.Printf("%s (ID: %d)", bike.FrameNumber, bike.BikeID)
				} else {
					fmt.Printf("%s", bike.FrameNumber)
				}
			}
			fmt.Println()
		}
	}

	// Bike ID verification
	if bikeID != "" {
		fmt.Println("\n--- Bike ID Verification ---")
		if r.bikeIDVerified {
			fmt.Printf("✓ Bike ID Verified: %s\n", bikeID)
			if r.matchedBike != nil {
				fmt.Printf("  Certificate matches bike from your account\n")
			}
		} else {
			fmt.Printf("✗ Bike ID verification failed for: %s\n", bikeID)
		}
	}

	// Public key verification
	if expectedPubKeyStr != "" {
		fmt.Println("\n--- Public Key Verification ---")
		if r.pubKeyVerified {
			fmt.Println("✓ Success: Public Key matches the Certificate signature.")
		} else {
			fmt.Println("✗ Warning: Key mismatch detected.")
		}
	}

	// User ID verification
	if expectedUserID != "" {
		fmt.Println("\n--- User ID Verification ---")
		if r.userIDVerified {
			fmt.Printf("✓ User ID Verified: %s\n", expectedUserID)
		} else {
			fmt.Printf("✗ User ID mismatch\n")
			fmt.Printf("  Expected: %s\n", expectedUserID)
			fmt.Printf("  Certificate: %s\n", fmt.Sprintf("%x", r.userID))
		}
	}
}

// getRoleDescription returns a human-readable description of the role value
func getRoleDescription(role uint8) string {
	switch role {
	case 0x00:
		return "Guest"
	case 0x0B:
		return "Guest"
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
	return int(uuid[6] >> 4)
}
