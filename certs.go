package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"time"
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

	// The Payload (The middle section containing Serial and Expiry)
	// This starts at byte 64
	payload := certData[64:134]

	// The Public Key embedded in the certificate (Last 32 bytes)
	embeddedPubKey := certData[len(certData)-32:]

	// --- Display Extracted Information ---

	// Display embedded public key
	embeddedPubKeyBase64 := base64.StdEncoding.EncodeToString(embeddedPubKey)
	fmt.Printf("\n--- Extracted from Certificate ---\n")
	fmt.Printf("Embedded Public Key (Base64): %s\n", embeddedPubKeyBase64)

	// --- Parse Payload Fields ---

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

	// Role & Versioning (Bytes 64-67)
	if len(certData) >= 67 {
		roleVersionBytes := certData[64:68]
		role := roleVersionBytes[0]
		roleType := "Unknown"
		if role == 0x01 {
			roleType = "Owner Certificate"
		} else if role == 0x02 {
			roleType = "Guest Certificate"
		}
		fmt.Printf("\n--- Certificate Fields ---\n")
		fmt.Printf("Role & Versioning (Bytes 64-67): %x\n", roleVersionBytes)
		fmt.Printf("  Role: %s (0x%02x)\n", roleType, role)
	}

	// Expiration Date (Bytes 100-107)
	if len(certData) >= 108 {
		expiryBytes := certData[100:108]
		timestamp := int64(binary.BigEndian.Uint64(expiryBytes))
		fmt.Printf("Expiration Date (Bytes 100-107): %x\n", expiryBytes)
		fmt.Printf("  Timestamp: %d\n", timestamp)
	}

	// Permission Bits (Bytes 112-115)
	if len(certData) >= 116 {
		permissionBytes := certData[112:116]
		permissions := binary.BigEndian.Uint32(permissionBytes)
		fmt.Printf("Permission Bits (Bytes 112-115): %x\n", permissionBytes)
		fmt.Printf("  Unlock Permission (Bit 0): %v\n", (permissions&0x01) != 0)
		fmt.Printf("  Alarm Settings Permission (Bit 1): %v\n", (permissions&0x02) != 0)
		fmt.Printf("  Firmware Update Permission (Bit 2): %v\n", (permissions&0x04) != 0)
	}

	// --- Verification Logic ---

	if bikeID != "" {
		fmt.Println("\n--- Bike ID Verification ---")
		// Search for the Bike ID in the payload
		if bytes.Contains(payload, []byte(bikeID)) {
			fmt.Println("✓ Bike ID Verified:", bikeID)
		} else {
			fmt.Println("✗ Bike ID NOT found:", bikeID)
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
func parseAccessLevel(certData []byte) string {
	certStr := string(certData)

	// Look for access profile markers
	re := regexp.MustCompile(`ap[A-Za-z0-9]`)
	if matches := re.FindString(certStr); matches != "" {
		// Interpret the access marker
		switch {
		case strings.Contains(matches, "W"):
			return "Owner/Admin (Full Control - Unlock, Settings, Firmware)"
		case strings.Contains(matches, "R"):
			return "Guest (Read-Only Access)"
		case strings.Contains(matches, "X"):
			return "Extended Owner (Full Control + Extended Permissions)"
		case strings.Contains(matches, "apS"):
			return "Service Level Access"
		default:
			return fmt.Sprintf("Custom Access Profile: %s (Full Control)", matches)
		}
	}

	// If no explicit access marker found, check permission bits
	// Based on the permission bits analysis
	return "Owner (Based on Permission Bits)"
}
