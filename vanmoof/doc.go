// Package vanmoof requests and checks the certificates that unlock VanMoof S5, A5 and
// Series 6 bikes over Bluetooth, as the vanmoof-certificates command does.
//
// A certificate binds an Ed25519 public key (see GenerateED25519) to a bike: with the
// matching private key, it unlocks the bike until it expires. Log in, list the account's
// bikes, request a certificate for one that UsesCertificates, and check it:
//
//	s, err := vanmoof.Login(email, password)
//	bikes, err := s.Bikes()
//	cert, err := s.RequestCertificate(bikes[0], publicKey)
//
//	res := vanmoof.CheckCertificate(cert, vanmoof.Expect{
//		PublicKey: publicKey,
//		Bike:      &bikes[0],
//	})
//	if !res.Valid {
//		log.Println(res.Errors)
//	}
//
// A Session renews its tokens as needed. To log in again later without the password,
// save Session.Tokens and continue with Resume. Keep the tokens and private keys secret:
// they let anyone unlock the bikes.
//
// GenerateCertificate goes the other way: it signs a certificate with a key of your own,
// for a bike whose module firmware you have changed to trust that key rather than
// VanMoof's. A stock bike trusts VanMoof's key alone and ignores it.
//
// Requests go over a copy of http.DefaultTransport that checks the TLS certificates of
// VanMoof's servers for revocation, with OCSP and CRLs, once each: a revoked one fails
// them with ErrRevoked, and one neither confirms with ErrRevocationUnknown, unless
// SetAllowUnknownRevocation.
//
// The package's other exported functions, such as GetCert, ShowKeys and
// ProcessCertificate, are the command's own: they prompt and print rather than return
// their results.
package vanmoof
