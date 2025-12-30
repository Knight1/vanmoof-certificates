package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

func processCertificate(certStr, expectedPubKeyStr, bikeID string, debug bool) {

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

	// The Payload (The middle section containing Serial and Expiry)
	// This starts at byte 64
	payload := certData[64:134]

	// The Public Key embedded in the certificate (Last 32 bytes)
	embeddedPubKey := certData[len(certData)-32:]

	// --- Display Extracted Information ---

	// Display signature
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	fmt.Printf("\n--- Extracted from Certificate ---\n")
	fmt.Printf("Signature (Base64): %s\n", signatureBase64)
	if debug {
		fmt.Printf("Signature (hex): %x\n", signature)
	}

	// Display embedded public key
	embeddedPubKeyBase64 := base64.StdEncoding.EncodeToString(embeddedPubKey)
	fmt.Printf("Embedded Public Key (Base64): %s\n", embeddedPubKeyBase64)

	// --- Parse Payload Fields ---

	// Extract Bike API ID from CBOR structure
	// Pattern: 0x61 'i' followed by 0x1a (uint32) and 4 bytes
	apiIDPattern := []byte{0x61, 0x69, 0x1a} // text string "i" followed by uint32 marker
	apiIDIdx := bytes.Index(certData, apiIDPattern)
	var apiID uint32
	if apiIDIdx >= 0 && apiIDIdx+7 <= len(certData) {
		// Read 4 bytes as big-endian uint32
		apiID = uint32(certData[apiIDIdx+3])<<24 |
			uint32(certData[apiIDIdx+4])<<16 |
			uint32(certData[apiIDIdx+5])<<8 |
			uint32(certData[apiIDIdx+6])
		fmt.Printf("Bike API ID: %d\n", apiID)
	}

	// Extract AFM (Authorized Frame Module)
	afmIdx := bytes.Index(payload, []byte("afm"))
	if afmIdx >= 0 && afmIdx+6 <= len(payload) {
		afmValue := string(payload[afmIdx+3 : afmIdx+16])
		afmValue = strings.TrimRight(afmValue, "\x00")
		fmt.Printf("AFM (Authorized Frame Module): %s\n", afmValue)
	}

	// Extract ABM (Authorized Bike Module)
	abmIdx := bytes.Index(payload, []byte("abm"))
	if abmIdx >= 0 && abmIdx+6 <= len(payload) {
		abmValue := string(payload[abmIdx+3 : abmIdx+16])
		abmValue = strings.TrimRight(abmValue, "\x00")
		fmt.Printf("ABM (Authorized Bike Module): %s\n", abmValue)
	}

	// Extract Access Level from full certificate data
	accessLevel := parseAccessLevel(certData)
	fmt.Printf("Access Level: %s\n", accessLevel)

	// --- Parse Certificate Fields ---

	// --- Verification Logic ---

	if bikeID != "" {
		fmt.Println("\n--- Bike ID Verification ---")
		// Try to match as frame number (string)
		if bytes.Contains(payload, []byte(bikeID)) {
			fmt.Println("✓ Bike ID Verified (Frame Number):", bikeID)
		} else {
			// Try to match as API ID (numeric)
			// Check if bikeID is a number and matches the API ID
			var matched bool
			if apiID > 0 {
				if bikeIDNum := bikeID; bikeIDNum != "" {
					// Try parsing as uint32
					var parsedID uint32
					fmt.Sscanf(bikeIDNum, "%d", &parsedID)
					if parsedID == apiID {
						fmt.Printf("✓ Bike ID Verified (API ID): %d\n", apiID)
						matched = true
					}
				}
			}
			if !matched {
				fmt.Printf("✗ Bike ID NOT found: %s (Frame not in payload, API ID: %d)\n", bikeID, apiID)
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
		if bytes.Equal(embeddedPubKey, pubKeyData[len(pubKeyData)-32:]) {
			fmt.Println("✓ Success: Public Key matches the Certificate signature.")
		} else {
			fmt.Println("✗ Warning: Key mismatch detected.")
		}
	}
}

// parseAccessLevel determines the access level from the certificate data
// The certificate is CBOR-encoded starting at byte 64 with a map structure
// containing a 'r' (role) field that indicates the access level
func parseAccessLevel(certData []byte) string {
	// The CBOR map starts at byte 64
	// Skip the first 64 bytes (signature/header)
	if len(certData) < 72 {
		return "Unknown (Certificate too short)"
	}

	// Search for the role field: 0x61 'r' followed by the role value
	// Pattern: 61 72 <value>
	rolePattern := []byte{0x61, 0x72} // text string "r"

	idx := bytes.Index(certData, rolePattern)
	if idx == -1 || idx+3 > len(certData) {
		return "Unknown (Role field not found)"
	}

	// The byte after 'r' contains the role value
	roleValue := certData[idx+2]

	// Interpret the role value
	// These values are based on reverse engineering the CBOR structure
	switch roleValue {
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
		return fmt.Sprintf("Unknown Role (0x%02X)", roleValue)
	}
}
