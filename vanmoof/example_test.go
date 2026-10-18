package vanmoof_test

import (
	"errors"
	"fmt"
	"log"

	"github.com/Knight1/vanmoof-certificates/vanmoof"
)

// Requesting and checking a certificate for each bike of the account that uses them
func Example() {
	// The Ed25519 public key to unlock the bikes with, e.g. from vanmoof.GenerateED25519
	publicKey := "Yd2bYMB3+vs4cCnDtPbcaM164KIl2zs05AK2jt/K6Gs="

	s, err := vanmoof.Login("user@example.com", "password")
	if err != nil {
		log.Fatal(err)
	}
	bikes, err := s.Bikes()
	if err != nil && !errors.Is(err, vanmoof.ErrSharedBikes) {
		log.Fatal(err)
	}
	userID, err := s.UserID() // known from Bikes, without another request
	if err != nil {
		log.Fatal(err)
	}

	for i, bike := range bikes {
		if !bike.UsesCertificates() {
			continue
		}
		cert, err := s.RequestCertificate(bike, publicKey)
		if err != nil {
			log.Printf("%s: %v", bike.FrameNumber, err)
			continue
		}
		res := vanmoof.CheckCertificate(cert, vanmoof.Expect{PublicKey: publicKey, Bike: &bikes[i], UserID: userID})
		if !res.Valid {
			log.Printf("%s: %v", bike.FrameNumber, res.Errors)
			continue
		}
		fmt.Printf("%s (%s): %s until %s\n", bike.FrameNumber, bike.Model(), res.AccessLevel(), res.Expires)
	}
}

// Continuing with tokens saved from an earlier session, without the password
func ExampleResume() {
	// Saved earlier from Session.Tokens, e.g. as JSON in a secret store
	var tokens vanmoof.Tokens

	s := vanmoof.Resume(tokens)
	bikes, err := s.Bikes()
	if errors.Is(err, vanmoof.ErrLoginRequired) {
		log.Fatal("the saved tokens expired: log in with vanmoof.Login again")
	}
	if err != nil && !errors.Is(err, vanmoof.ErrSharedBikes) {
		log.Fatal(err)
	}
	fmt.Println(len(bikes), "bikes")

	// The session may have renewed its tokens: save s.Tokens() again
}
