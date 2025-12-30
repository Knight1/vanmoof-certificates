package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
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

func processCertificate(certStr, expectedPubKeyStr, bikeID, expectedUserID string, debug bool) {

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
	}

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
			}
		case "f": // Frame ID (was "fm")
			if v, ok := value.(string); ok {
				frameID = []byte(v)
			}
		case "b": // Bike ID (was "bm")
			if v, ok := value.(string); ok {
				bikeIDBytes = []byte(v)
			}
		case "e":
			if v, ok := value.(uint64); ok {
				expiry = uint32(v)
			}
		case "r":
			if v, ok := value.(uint64); ok {
				role = uint8(v)
			}
		case "u":
			userID, _ = value.([]byte)
		case "p":
			publicKey, _ = value.([]byte)
		}
	}

	// Display parsed fields
	fmt.Printf("Bike API ID: %d\n", apiID)
	fmt.Printf("AFM (Authorized Frame Module): %s\n", string(frameID))
	fmt.Printf("ABM (Authorized Bike Module): %s\n", string(bikeIDBytes))

	// Convert and display expiry timestamp
	expiryTime := time.Unix(int64(expiry), 0)
	fmt.Printf("Certificate Expiry: %s (Unix: %d)\n", expiryTime.Format("2006-01-02 15:04:05 MST"), expiry)

	// Display access level
	accessLevel := getRoleDescription(role)
	fmt.Printf("Access Level: %s\n", accessLevel)

	// Display user ID
	fmt.Printf("User ID: %x\n", userID)

	// Display embedded public key
	embeddedPubKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)
	fmt.Printf("Embedded Public Key (Base64): %s\n", embeddedPubKeyBase64)

	// --- Parse Certificate Fields ---

	// --- Verification Logic ---

	if bikeID != "" {
		fmt.Println("\n--- Bike ID Verification ---")
		// Try to match as frame number (string)
		frameIDStr := string(frameID)
		bikeIDStr := string(bikeIDBytes)
		if frameIDStr == bikeID || bikeIDStr == bikeID {
			fmt.Println("✓ Bike ID Verified (Frame Number):", bikeID)
		} else {
			// Try to match as API ID (numeric)
			var matched bool
			var parsedID uint32
			if _, err := fmt.Sscanf(bikeID, "%d", &parsedID); err == nil && parsedID == apiID {
				fmt.Printf("✓ Bike ID Verified (API ID): %d\n", apiID)
				matched = true
			}
			if !matched {
				fmt.Printf("✗ Bike ID NOT found: %s (Frame: %s, API ID: %d)\n", bikeID, bikeIDStr, apiID)
			}
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
