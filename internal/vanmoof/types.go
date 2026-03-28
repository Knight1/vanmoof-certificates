package vanmoof

import "encoding/json"

// API response types
type AuthResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

// Cached tokens stored on disk (keyed by email in the cache file)
type CachedTokens struct {
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

type BikeData struct {
	Name          string `json:"name"`
	BikeID        int    `json:"id"`
	FrameNumber   string `json:"frameNumber"`
	FrameSerial   string `json:"frameSerial"`
	BleProfile    string `json:"bleProfile"`
	MainEcuSerial string `json:"mainEcuSerial"`
}

type CustomerData struct {
	Data struct {
		UUID  string     `json:"uuid"`
		Bikes []BikeData `json:"bikes"`
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

type CertificateResponse struct {
	Certificate string `json:"certificate"`
}

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

	// Match results
	matchedBike    *BikeData
	bikeIDVerified bool
	pubKeyVerified bool
	userIDVerified bool
}
