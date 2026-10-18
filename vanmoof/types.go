package vanmoof

import (
	"encoding/json"
	"time"
)

// API response types
type AuthResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

// Tokens are a logged-in session's credentials (see Session.Tokens and Resume), and what
// the command line tool caches per email address. Keep them secret: they give access to
// the account, including creating certificates that unlock its bikes.
type Tokens struct {
	AuthToken    string `json:"auth_token"`
	AppToken     string `json:"app_token"`
	RefreshToken string `json:"refresh_token"`
}

// Refresh token request body
type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type AppTokenResponse struct {
	Token string `json:"token"`
}

// httpError is the error doHTTPRequest returns for an HTTP error response (status >= 400)
type httpError struct {
	statusCode int
	body       string // truncated to 500 bytes
}

// Bike is one of the account's bikes, its own or one shared with it (see Session.Bikes)
type Bike struct {
	Name          string `json:"name"`
	BikeID        int    `json:"id"` // 0 for a bike shared with the account
	FrameNumber   string `json:"frameNumber"`
	FrameSerial   string `json:"frameSerial"`
	BleProfile    string `json:"bleProfile"`
	MainEcuSerial string `json:"mainEcuSerial"`
	Owner         string `json:"-"` // the owner's name, for a bike shared with the account
}

// BikeDetail is an entry of bikeDetails in the getCustomerData response
type BikeDetail struct {
	BikeID         int    `json:"id"`
	Name           string `json:"name"`
	FrameNumber    string `json:"frameNumber"`
	MacAddress     string `json:"macAddress"`
	BleProfile     string `json:"bleProfile"`
	MessagesViaBLE string `json:"messagesViaBLE"`
	Key            struct {
		EncryptionKey string `json:"encryptionKey"`
	} `json:"key"`
}

// BikeMessage is one entry of the getBikeMessages response: a message queued for
// delivery to the bike the next time it connects over BLE.
type BikeMessage struct {
	Content string `json:"content"`
}

type CustomerData struct {
	Data struct {
		UUID  string `json:"uuid"`
		Bikes []Bike `json:"bikes"`
		// BikeDetails carries the per-bike BLE key, which getCustomerData does not put in Bikes
		BikeDetails []BikeDetail `json:"bikeDetails"`
	} `json:"data"`
}

// Vehicle Registry API response types (for shared bikes on S5/S6)
type VehicleAccess struct {
	VehicleID  string `json:"vehicle_id"`
	Role       string `json:"role"`
	RiderName  string `json:"rider_name"`
	RiderEmail string `json:"rider_email"`
	SKU        string `json:"sku"`
	BleID      string `json:"ble_id"`
	Name       string `json:"name"`
	BleProfile string `json:"ble_profile"`
	OwnerID    string `json:"owner_id"`
	OwnerName  string `json:"owner_name"`
	OwnerEmail string `json:"owner_email"`
	StartsAt   string `json:"starts_at"`
	ExpiresAt  string `json:"expires_at"`
}

type RiderVehiclesResponse struct {
	RiderID       string          `json:"rider_id"`
	VehicleAccess []VehicleAccess `json:"vehicle_access"`
}

// Bike sharing invitations response
type BikeSharingInvitationsResponse struct {
	Invitations []json.RawMessage `json:"invitations"`
	Hash        string            `json:"hash"`
}

type CertificateRequest struct {
	PublicKey string `json:"public_key"`
}

// certResult collects all parsed certificate data and validation outcomes
type certResult struct {
	// Parsed data
	signature []byte
	apiID     uint32
	frameID   []byte
	bikeID    []byte
	expiry    uint32
	role      uint8
	userID    []byte
	publicKey []byte

	// Validation
	errors   []string
	warnings []string
	notes    []string // informational only, shown but never makes a certificate invalid

	// Match results
	matchedBike       *Bike
	bikeIDVerified    bool
	pubKeyVerified    bool
	userIDVerified    bool
	signatureVerified bool // a known CA key verified the signature (never for S6 yet)
	perBikeKey        bool // an S6 certificate, whose signing key isn't known yet
}

// Expect is what CheckCertificate checks a certificate against. Each field is optional:
// one left empty isn't checked.
type Expect struct {
	PublicKey string // the base64 Ed25519 public key it has to be for, e.g. from GenerateED25519
	Bike      *Bike  // the bike it has to be for
	UserID    string // the user it has to be for (Session.UserID)
	Bikes     []Bike // the account's bikes, to tell which one it's for (MatchedBike)
}

// CertificateResult is what CheckCertificate found out about a certificate
type CertificateResult struct {
	// Valid reports whether every check passed. For an S6 that can't include the
	// signature yet, as no S6 signing key is known (see SignatureVerified).
	Valid    bool
	Errors   []string // why it isn't valid
	Warnings []string // suspicious, but not invalid, e.g. an expiry far in the future
	Notes    []string // for information, e.g. why the signature couldn't be verified

	SignatureVerified bool  // a known VanMoof key verified the signature
	BikeVerified      bool  // it's for Expect.Bike
	PublicKeyVerified bool  // it's for Expect.PublicKey
	UserIDVerified    bool  // it's for Expect.UserID
	MatchedBike       *Bike // the bike of Expect.Bikes it's for, if any

	ID          uint32 // certificate ID, random per certificate
	FrameModule string // the frame module (AFM) it's for, normally the frame number
	BikeModule  string // the bike module (ABM) it's for
	Expires     time.Time
	Role        uint8  // access level, see AccessLevel
	UserID      []byte // the user's 16 byte UUID
	PublicKey   []byte // the 32 byte Ed25519 public key it's for
	Signature   []byte // Ed25519 signature of Payload
	Payload     []byte // the CBOR encoded fields above
}
