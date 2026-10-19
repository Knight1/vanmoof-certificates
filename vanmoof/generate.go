package vanmoof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

// certEncMode encodes certificate payloads as canonical CBOR, so the bytes the signature
// covers are deterministic: the same fields always produce the same certificate.
var certEncMode = must(cbor.CanonicalEncOptions().EncMode())

// CertificateParams are the fields GenerateCertificate puts in a certificate. They mirror
// what CheckCertificate reads back out of one (see CertificateResult).
type CertificateParams struct {
	ID          uint32    // the certificate's ID ('i'); VanMoof's are random per certificate
	FrameModule string    // the frame module ('f', AFM) it's for, normally the frame number
	BikeModule  string    // the bike module ('b', ABM) it's for, often the same
	Expires     time.Time // when it expires ('e'), to the second, before the year 2106
	Role        uint8     // the access level ('r'), see AccessLevel and the roles CheckCertificate names
	UserID      []byte    // the user's 16-byte UUID ('u')
	PublicKey   []byte    // the 32-byte Ed25519 public key to authorize ('p')
}

// GenerateCertificate builds a bike certificate for the fields in params and signs its CBOR
// payload with signingKey, returning it base64-encoded in the format CheckCertificate reads.
//
// It signs with your own key, not VanMoof's, so the certificate unlocks only a bike whose
// module firmware you have changed to trust signingKey's public half: a stock bike trusts
// VanMoof's key alone and ignores it. CheckCertificate therefore reports a certificate from
// here as not signed by VanMoof, which is expected. Keep signingKey and the certificate
// secret: together with the authorized private key, they unlock the bike.
func GenerateCertificate(params CertificateParams, signingKey ed25519.PrivateKey) (string, error) {
	if len(signingKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("signing key is %d bytes, not %d", len(signingKey), ed25519.PrivateKeySize)
	}
	if params.FrameModule == "" {
		return "", errors.New("frame module (AFM) is empty")
	}
	if params.BikeModule == "" {
		return "", errors.New("bike module (ABM) is empty")
	}
	// CBOR text strings, like 'f' and 'b', are UTF-8: a certificate with anything else in
	// them is one no parser (the bike's included) accepts, so refuse rather than emit it.
	if !utf8.ValidString(params.FrameModule) {
		return "", errors.New("frame module (AFM) is not valid UTF-8")
	}
	if !utf8.ValidString(params.BikeModule) {
		return "", errors.New("bike module (ABM) is not valid UTF-8")
	}
	if len(params.PublicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("public key is %d bytes, not %d", len(params.PublicKey), ed25519.PublicKeySize)
	}
	if len(params.UserID) != 16 {
		return "", fmt.Errorf("user UUID is %d bytes, not 16", len(params.UserID))
	}
	// Unix seconds have to fit the certificate's uint32 'e' field, i.e. be after 1970 and
	// before 2106. The zero time (year 1) is negative here, so this rejects an unset expiry.
	expiry := params.Expires.Unix()
	if expiry <= 0 || expiry > math.MaxUint32 {
		return "", fmt.Errorf("expiry %s is out of range (it must be between 1970 and 2106)", params.Expires.UTC().Format(time.RFC3339))
	}

	// The field types match what parseCertificate expects: strings for 'f'/'b', unsigned
	// integers for 'i'/'e'/'r', byte strings for 'u'/'p'. Marshaling them can't fail.
	payload := must(certEncMode.Marshal(map[string]any{
		"i": params.ID,
		"f": params.FrameModule,
		"b": params.BikeModule,
		"e": uint32(expiry),
		"r": params.Role,
		"u": params.UserID,
		"p": params.PublicKey,
	}))

	// signature (64 bytes) + payload, as analyzeCertificate splits it back apart
	signature := ed25519.Sign(signingKey, payload)
	return base64.StdEncoding.EncodeToString(slices.Concat(signature, payload)), nil
}

// genConfig is the JSON file GenerateCert reads: which key to authorize, signed with which
// key, for which bike, as whom, and for how long. Unknown fields are rejected, to catch typos.
type genConfig struct {
	SigningKey   string `json:"signing_key"`   // base64 Ed25519 private key that signs: the 64-byte key -genkey prints, or a 32-byte seed
	PublicKey    string `json:"public_key"`    // base64 Ed25519 public key to authorize (32 bytes); the signing key's own by default
	AFM          string `json:"afm"`           // the frame module, e.g. the frame number
	ABM          string `json:"abm"`           // the bike module; the AFM by default
	Role         string `json:"role"`          // the access level: a name like "Owner" or a number like 7 or 0x07
	UserUUID     string `json:"user_uuid"`     // the user's UUID, hyphenated or not
	ValidityDays int    `json:"validity_days"` // days from now until it expires, an alternative to expires
	Expires      string `json:"expires"`       // when it expires, as RFC 3339 (e.g. 2027-01-02T15:04:05Z); overrides validity_days
	ID           uint32 `json:"id"`            // the certificate's ID; random if left out
}

// parseSigningKey decodes a base64 Ed25519 private key: the 64-byte key -genkey prints, or a
// 32-byte seed it expands into one.
func parseSigningKey(s string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	default:
		return nil, fmt.Errorf("decodes to %d bytes, not a %d-byte private key or %d-byte seed", len(raw), ed25519.PrivateKeySize, ed25519.SeedSize)
	}
}

// parseAuthorizedKey decodes the base64 public key to authorize. Empty, it defaults to the
// signing key's own public half, for authorizing your own key with your own signature.
func parseAuthorizedKey(s string, signingKey ed25519.PrivateKey) ([]byte, error) {
	if strings.TrimSpace(s) == "" {
		return slices.Clone(signingKey.Public().(ed25519.PublicKey)), nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	// Some keys carry a leading 0x00, which IsValidEd25519PublicKey accepts too
	if len(raw) == ed25519.PublicKeySize+1 && raw[0] == 0 {
		raw = raw[1:]
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("decodes to %d bytes, not a %d-byte public key", len(raw), ed25519.PublicKeySize)
	}
	return raw, nil
}

// parseUserUUID decodes a UUID, hyphenated or not, into its 16 bytes.
func parseUserUUID(s string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
	if err != nil {
		return nil, fmt.Errorf("not hexadecimal: %w", err)
	}
	if len(raw) != 16 {
		return nil, fmt.Errorf("is %d bytes, not 16", len(raw))
	}
	return raw, nil
}

// parseRole turns a role name (such as "Owner", any case) or a number (decimal, or 0x.. hex)
// into its byte value.
func parseRole(s string) (uint8, error) {
	s = strings.TrimSpace(s)
	for v, name := range roleNames {
		if strings.EqualFold(name, s) {
			return v, nil
		}
	}
	n, err := strconv.ParseUint(s, 0, 8)
	if err != nil {
		return 0, fmt.Errorf("%q is not a role name or a number from 0 to 255", s)
	}
	return uint8(n), nil
}

// expiryFromConfig returns when the certificate expires: the explicit expires if set, else
// validity_days from now.
func expiryFromConfig(cfg genConfig, now time.Time) (time.Time, error) {
	if s := strings.TrimSpace(cfg.Expires); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}, fmt.Errorf("expires %q is not an RFC 3339 time like 2027-01-02T15:04:05Z: %w", s, err)
		}
		return t, nil
	}
	if cfg.ValidityDays > 0 {
		return now.Add(time.Duration(cfg.ValidityDays) * 24 * time.Hour), nil
	}
	return time.Time{}, errors.New("set expires (an RFC 3339 time) or validity_days (a positive number of days)")
}

// paramsFromConfig turns a parsed config into the parameters and signing key for
// GenerateCertificate. now is when validity_days counts from.
func paramsFromConfig(cfg genConfig, now time.Time) (CertificateParams, ed25519.PrivateKey, error) {
	fail := func(field string, err error) (CertificateParams, ed25519.PrivateKey, error) {
		return CertificateParams{}, nil, fmt.Errorf("%s: %w", field, err)
	}

	signingKey, err := parseSigningKey(cfg.SigningKey)
	if err != nil {
		return fail("signing_key", err)
	}
	publicKey, err := parseAuthorizedKey(cfg.PublicKey, signingKey)
	if err != nil {
		return fail("public_key", err)
	}
	userID, err := parseUserUUID(cfg.UserUUID)
	if err != nil {
		return fail("user_uuid", err)
	}
	role, err := parseRole(cfg.Role)
	if err != nil {
		return fail("role", err)
	}
	expires, err := expiryFromConfig(cfg, now)
	if err != nil {
		return CertificateParams{}, nil, err
	}

	// The bike module defaults to the frame module, which is the common case
	afm, abm := strings.TrimSpace(cfg.AFM), strings.TrimSpace(cfg.ABM)
	if abm == "" {
		abm = afm
	}
	return CertificateParams{
		ID: cfg.ID, FrameModule: afm, BikeModule: abm,
		Expires: expires, Role: role, UserID: userID, PublicKey: publicKey,
	}, signingKey, nil
}

// randomCertID returns a random certificate ID, as VanMoof's certificates have one.
func randomCertID() uint32 {
	var b [4]byte
	rand.Read(b[:]) // never fails
	return binary.BigEndian.Uint32(b[:])
}

// GenerateCert reads the JSON config at path and prints a self-signed bike certificate for
// the key it names (see genConfig for the fields, and USAGE.md). The certificate is a secret,
// like the signing key: -redact hides it, so a usable one you have to generate yourself. It
// works only on a bike whose firmware trusts your signing key, not on a stock VanMoof bike.
func GenerateCert(path string, debug bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	return generateCert(data, debug)
}

// generateCert is GenerateCert on the config bytes already read, so it can be tested and
// fuzzed without a file.
func generateCert(data []byte, debug bool) error {
	var cfg genConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}

	params, signingKey, err := paramsFromConfig(cfg, time.Now())
	if err != nil {
		return err
	}
	defer clear(signingKey) // wipe the private key once we're done signing (defense in depth)
	if params.ID == 0 {
		params.ID = randomCertID()
	}

	cert, err := GenerateCertificate(params, signingKey)
	if err != nil {
		return err
	}

	printGeneratedCert(params, signingKey.Public().(ed25519.PublicKey), cert, debug)
	return nil
}

// printGeneratedCert prints a generated certificate and the fields it holds. The certificate
// and the keys are secrets the regular output shows on purpose, so -redact hides them.
func printGeneratedCert(params CertificateParams, signingPub ed25519.PublicKey, cert string, debug bool) {
	fmt.Println("Generated a self-signed certificate (it works only on a bike whose firmware trusts your signing key):")
	fmt.Printf("  AFM (frame module):   %s\n", RedactID(params.FrameModule))
	fmt.Printf("  ABM (bike module):    %s\n", RedactID(params.BikeModule))
	fmt.Printf("  Access level:         %s\n", getRoleDescription(params.Role))
	fmt.Printf("  User UUID:            %s\n", Redact(formatUUID(params.UserID)))
	fmt.Printf("  Authorized key:       %s\n", Redact(base64.StdEncoding.EncodeToString(params.PublicKey)))
	fmt.Printf("  Expires:              %s\n", params.Expires.UTC().Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("  Signing key (public): %s\n", Redact(base64.StdEncoding.EncodeToString(signingPub)))
	if debug {
		fmt.Printf("  Certificate ID:       %s\n", RedactID(fmt.Sprint(params.ID)))
	}
	fmt.Println("Certificate:")
	fmt.Println(Redact(cert))
}
