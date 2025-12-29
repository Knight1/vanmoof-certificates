package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

func processCertificate(certStr, expectedPubKeyStr, bikeID string) {

	// Decode the certificate
	certData, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		fmt.Println("Error decoding certificate:", err)
		return
	}

	fmt.Printf("Total Certificate Length: %d bytes\n", len(certData))

	// --- 3. Extract Components ---

	// The Payload (The middle section containing Serial and Expiry)
	// This starts at byte 64
	payload := certData[64:134]

	// The Public Key embedded in the certificate (Last 32 bytes)
	embeddedPubKey := certData[len(certData)-32:]

	// --- 4. Verification Logic ---

	if bikeID != "" {
		fmt.Println("--- Bike Identification ---")
		// Search for the Bike ID in the payload
		if bytes.Contains(payload, []byte(bikeID)) {
			fmt.Println("Bike ID Verified:", bikeID)
		} else {
			fmt.Println("Bike ID NOT found:", bikeID)
		}
	}

	if expectedPubKeyStr != "" {
		fmt.Println("\n--- Key Comparison ---")
		// Decode the provided public key
		pubKeyData, err := base64.StdEncoding.DecodeString(expectedPubKeyStr)
		if err != nil {
			fmt.Println("Error decoding public key:", err)
			return
		}
		// Note: The Public Key string has a leading 0x00 byte (prefix)
		// We compare the last 32 bytes of your key to the embedded key
		if bytes.Equal(embeddedPubKey, pubKeyData[len(pubKeyData)-32:]) {
			fmt.Println("Success: Public Key matches the Certificate signature.")
		} else {
			fmt.Println("Warning: Key mismatch detected.")
		}
	}

	// --- 5. Accessing the 'Unaccounted For' Bytes ---
	// The expiry timestamp is usually a 4 or 8 byte integer within the payload
	expiryBytes := certData[100:108]
	fmt.Printf("\nRaw Expiry Bytes (Hex): %x\n", expiryBytes)
}
