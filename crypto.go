package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func generateED25519() (string, string, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key pair: %w", err)
	}

	privKeyB64 := base64.StdEncoding.EncodeToString(privKey)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	return privKeyB64, pubKeyB64, nil
}

func createCertificate(bikeID, pubKey, appToken string, debug bool) (string, error) {
	certReq := CertificateRequest{
		PublicKey: pubKey,
	}

	reqBody, err := json.Marshal(certReq)
	if err != nil {
		return "", err
	}

	headers := map[string]string{
		"Authorization": "Bearer " + appToken,
		"User-Agent":    UserAgent,
		"Content-Type":  "application/json",
	}

	url := fmt.Sprintf(BikeApiBaseURL+"/bikes/%s/create_certificate", bikeID)
	body, err := doHTTPRequest("POST", url, bytes.NewBuffer(reqBody), headers, debug)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
