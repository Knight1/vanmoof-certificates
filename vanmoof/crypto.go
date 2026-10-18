package vanmoof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
)

// GenerateED25519 generates an Ed25519 key pair in base64: the 64 byte private key (seed
// and public key), and the 32 byte public key to request certificates for. Keep the
// private key secret: with a certificate for its public key, it unlocks the bike.
func GenerateED25519() (privateKey, publicKey string, err error) {
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
		"Content-Type":  "application/json",
	}

	url := fmt.Sprintf(bikeApiBaseURL+"/bikes/%s/create_certificate", url.PathEscape(bikeID))
	body, err := doHTTPRequest("POST", url, bytes.NewBuffer(reqBody), headers, debug)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
