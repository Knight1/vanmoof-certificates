package vanmoof

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ProcessCertificate parses and checks a certificate given with -cert, against the
// optional -pubkey and -framenumber.
func ProcessCertificate(certStr, expectedPubKeyStr, frameNumber string, debug bool) {
	var expectedBike *BikeData
	if frameNumber != "" {
		expectedBike = &BikeData{FrameNumber: frameNumber}
	}
	checkCertificate(certStr, expectedPubKeyStr, expectedBike, "", nil, debug)
}

// checkCertificate parses a certificate and checks it against the expected public key,
// bike and user ID, each skipped if empty. expectedBike is the bike the certificate was
// requested for, or the one given with -framenumber. bikes are the account's bikes, to report
// which one the certificate matches.
func checkCertificate(certStr, expectedPubKeyStr string, expectedBike *BikeData, expectedUserID string, bikes []BikeData, debug bool) {
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
	verifyBike(&r, expectedBike)
	verifyPublicKey(&r, expectedPubKeyStr)
	verifyUserID(&r, expectedUserID)

	// Verify the certificate signature against known CA keys. A match is silent, a
	// mismatch is an error, except on S6 where it only means the key isn't known yet.
	perBikeKey := isS6Certificate(r, expectedBike)
	verified, hasKeys := verifyCertificateSignature(r.signature, certData[64:])
	r.signatureVerified = verified
	if hasKeys && !verified {
		if perBikeKey {
			// No S6 signing key is known yet, so a mismatch against the known CA keys
			// says nothing about the certificate and is not an error.
			r.notes = append(r.notes, s6SignatureNote)
		} else {
			r.errors = append(r.errors, "Signature INVALID: does not verify against any known VanMoof CA key")
		}
	}

	// Output
	if debug {
		printVerbose(r, certData, expectedPubKeyStr, expectedBike, expectedUserID, bikes)
		validateCertificateSignature(r.signature, certData[64:], debug, perBikeKey)
		for _, n := range r.notes {
			fmt.Printf("  Info: %s\n", n)
		}
	} else {
		printCompact(r)
	}
}

// parseCertificate extracts and validates all fields from raw certificate bytes
const s6SignatureNote = "Signature verification unavailable: no S6 certificate signing key is known yet"

// isS6Certificate reports whether the certificate belongs to an S6. The BLE profile of
// the bike it was requested for decides, or else that of the account bike it matches.
// Without either (offline), the frame number shape decides, which some SA5s share.
func isS6Certificate(r certResult, requestedBike *BikeData) bool {
	switch {
	case requestedBike != nil && requestedBike.BleProfile != "":
		return requestedBike.BleProfile == "ELECTRIFIED_2025"
	case r.matchedBike != nil && r.matchedBike.BleProfile != "":
		return r.matchedBike.BleProfile == "ELECTRIFIED_2025"
	default:
		return s6FrameNumberRegexp.MatchString(string(r.frameID))
	}
}

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
		r.warnings = append(r.warnings, fmt.Sprintf("Frame ID (f) has invalid format: %s", RedactID(string(r.frameID))))
	}

	// Validate bike ID format
	if len(r.bikeID) == 0 {
		r.errors = append(r.errors, "Bike ID (b) is empty")
	} else if !ValidateFrameNumber(string(r.bikeID)) {
		r.warnings = append(r.warnings, fmt.Sprintf("Bike ID (b) has invalid format: %s", RedactID(string(r.bikeID))))
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

// verifyBike checks the certificate against the bike it should be for
func verifyBike(r *certResult, bike *BikeData) {
	if bike == nil {
		return
	}

	frameIDStr := string(r.frameID)
	bikeIDStr := string(r.bikeID)

	switch {
	case bike.BikeID != 0:
		// One of the account's own bikes, with its module serials from the API
		if (frameIDStr == bike.FrameNumber || frameIDStr == bike.FrameSerial) &&
			(bikeIDStr == bike.FrameNumber || bikeIDStr == bike.FrameSerial || bikeIDStr == bike.MainEcuSerial) {
			r.bikeIDVerified = true
		} else {
			r.errors = append(r.errors, fmt.Sprintf("Bike ID %s mismatch: bike has frame %s, certificate has AFM %s, ABM %s",
				RedactID(fmt.Sprint(bike.BikeID)), RedactID(bike.FrameNumber), RedactID(frameIDStr), RedactID(bikeIDStr)))
		}
	default:
		// Only the frame number is known: a shared bike, or -framenumber
		if frameIDStr == bike.FrameNumber || bikeIDStr == bike.FrameNumber {
			r.bikeIDVerified = true
		} else {
			r.errors = append(r.errors, fmt.Sprintf("Bike frame %s not found in certificate (AFM: %s, ABM: %s)",
				RedactID(bike.FrameNumber), RedactID(frameIDStr), RedactID(bikeIDStr)))
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
	if len(pubKeyData) < 32 {
		r.errors = append(r.errors, fmt.Sprintf("Public key too short: expected at least 32 bytes, got %d", len(pubKeyData)))
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
	expectedClean := strings.ToLower(strings.ReplaceAll(expectedUserID, "-", ""))
	if certUserID == expectedClean {
		r.userIDVerified = true
	} else {
		r.errors = append(r.errors, fmt.Sprintf("User ID mismatch: expected %s, certificate has %s", Redact(expectedUserID), Redact(certUserID)))
	}
}

// printCompact prints a one-line summary (normal mode)
func printCompact(r certResult) {
	frameIDStr := string(r.frameID)
	expiryTime := time.Unix(int64(r.expiry), 0)
	accessLevel := getRoleDescription(r.role)

	if len(r.errors) == 0 {
		parts := []string{RedactID(frameIDStr), accessLevel, "expires " + expiryTime.Format("2006-01-02 15:04:05 MST")}
		if r.matchedBike != nil {
			parts = append(parts, "bike matched")
		}
		if r.pubKeyVerified {
			parts = append(parts, "pubkey ok")
		}
		if r.userIDVerified {
			parts = append(parts, "user ok")
		}
		verdict := "Certificate valid"
		if !r.signatureVerified {
			verdict = "Certificate valid, but signature not verified"
		}
		fmt.Printf("%s: %s\n", verdict, strings.Join(parts, ", "))
	} else {
		fmt.Printf("Certificate INVALID: %d error(s), %d warning(s)\n", len(r.errors), len(r.warnings))
		for _, e := range r.errors {
			fmt.Printf("  ✗ %s\n", e)
		}
	}
	// Warnings never make a certificate invalid, but are always shown
	for _, w := range r.warnings {
		fmt.Printf("  ⚠ %s\n", w)
	}
	for _, n := range r.notes {
		fmt.Printf("  Note: %s\n", n)
	}
}

// printVerbose prints the full detailed output (debug mode)
func printVerbose(r certResult, certData []byte, expectedPubKeyStr string, expectedBike *BikeData, expectedUserID string, bikes []BikeData) {
	fmt.Printf("Total Certificate Length: %d bytes\n", len(certData))
	fmt.Printf("Decoded Certificate (hex): %s\n", Redact(fmt.Sprintf("%x", certData)))

	signature := certData[0:64]
	cborPayload := certData[64:]

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	fmt.Printf("\n--- Extracted from Certificate ---\n")
	fmt.Printf("Signature (Base64): %s\n", Redact(signatureBase64))
	fmt.Printf("Signature (hex): %s\n", Redact(fmt.Sprintf("%x", signature)))
	fmt.Printf("CBOR Payload length: %d bytes\n", len(cborPayload))
	fmt.Printf("CBOR Payload (hex): %s\n", Redact(fmt.Sprintf("%x", cborPayload)))

	fmt.Println("\n[DEBUG] Signature Analysis:")
	fmt.Printf("  Signature is %d bytes (Ed25519 signature)\n", len(signature))
	fmt.Printf("  R component (first 32 bytes): %s\n", Redact(fmt.Sprintf("%x", signature[:32])))
	fmt.Printf("  S component (last 32 bytes):  %s\n", Redact(fmt.Sprintf("%x", signature[32:])))

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
	fmt.Printf("Certificate ID: %s\n", RedactID(fmt.Sprint(r.apiID)))

	frameIDStr := string(r.frameID)
	fmt.Printf("AFM (Authorized Frame Module): %s", RedactID(frameIDStr))
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
	fmt.Printf("ABM (Authorized Bike Module): %s", RedactID(bikeIDStr))
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
	fmt.Printf("User ID: %s", Redact(userUUIDStr))
	if validateUUID(r.userID) {
		fmt.Printf(" ✓ Valid UUID v%d\n", getUUIDVersion(r.userID))
	} else {
		fmt.Printf(" ✗ Invalid UUID\n")
	}

	embeddedPubKeyBase64 := base64.StdEncoding.EncodeToString(r.publicKey)
	fmt.Printf("Embedded Public Key (Base64): %s\n", Redact(embeddedPubKeyBase64))

	// Bike match summary
	if len(bikes) > 0 {
		fmt.Println("\n--- Certificate Validation Summary ---")
		if r.matchedBike != nil {
			fmt.Printf("✓ Certificate matches one of your bikes\n")
			if r.matchedBike.BikeID != 0 {
				fmt.Printf("  Matched Bike ID: %s\n", RedactID(fmt.Sprint(r.matchedBike.BikeID)))
			}
			fmt.Printf("  Bike Name: %s\n", Redact(r.matchedBike.Name))
			fmt.Printf("  Frame Number: %s\n", RedactID(r.matchedBike.FrameNumber))
		} else {
			fmt.Printf("✗ Certificate does NOT match any of your bikes\n")
			fmt.Printf("  Certificate AFM: %s\n", RedactID(frameIDStr))
			fmt.Printf("  Certificate ABM: %s\n", RedactID(bikeIDStr))
			fmt.Printf("  Your bikes: ")
			for i, bike := range bikes {
				if i > 0 {
					fmt.Printf(", ")
				}
				if bike.BikeID != 0 {
					fmt.Printf("%s (ID: %s)", RedactID(bike.FrameNumber), RedactID(fmt.Sprint(bike.BikeID)))
				} else {
					fmt.Printf("%s", RedactID(bike.FrameNumber))
				}
			}
			fmt.Println()
		}
	}

	// Bike ID verification
	if expectedBike != nil {
		bikeLabel := RedactID(expectedBike.FrameNumber)
		if expectedBike.BikeID != 0 {
			bikeLabel = RedactID(fmt.Sprint(expectedBike.BikeID))
		}
		fmt.Println("\n--- Bike ID Verification ---")
		if r.bikeIDVerified {
			fmt.Printf("✓ Bike ID Verified: %s\n", bikeLabel)
			if r.matchedBike != nil {
				fmt.Printf("  Certificate matches bike from your account\n")
			}
		} else {
			fmt.Printf("✗ Bike ID verification failed for: %s\n", bikeLabel)
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
			fmt.Printf("✓ User ID Verified: %s\n", Redact(expectedUserID))
		} else {
			fmt.Printf("✗ User ID mismatch\n")
			fmt.Printf("  Expected: %s\n", Redact(expectedUserID))
			fmt.Printf("  Certificate: %s\n", Redact(fmt.Sprintf("%x", r.userID)))
		}
	}
}

// getRoleDescription returns a human-readable description of the role value
func getRoleDescription(role uint8) string {
	switch role {
	case 0x07:
		return "Owner"
	case 0x0B:
		return "Guest"
	case 0x11:
		return "Bike Doctor"
	case 0x16:
		return "Bike Hunter"
	case 0x37:
		return "QA Engineer"
	case 0x42:
		return "R&D Engineer"
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
