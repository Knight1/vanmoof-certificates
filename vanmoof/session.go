package vanmoof

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// ErrLoginRequired means the session's tokens expired or were rejected, and renewing them
// failed: log in again with Login.
var ErrLoginRequired = errors.New("vanmoof: login required")

// ErrSharedBikes is wrapped by the error Session.Bikes returns when it got the account's
// own bikes, but couldn't look up the ones shared with it.
var ErrSharedBikes = errors.New("vanmoof: couldn't look up the bikes shared with the account")

// Session is a logged-in VanMoof account. Its methods renew its tokens as needed, and it's
// safe to use from several goroutines at once.
type Session struct {
	mu     sync.Mutex
	tokens Tokens
	userID string // from the account's customer data, once fetched
	debug  bool   // print the requests, for the command line tool's -debug
}

// Login logs in with the account's email address and password. Unlike the command line
// tool, it never prompts and doesn't cache the tokens: save Session.Tokens for Resume.
func Login(email, password string) (*Session, error) {
	return passwordLogin(email, password, false)
}

func passwordLogin(email, password string, debug bool) (*Session, error) {
	authToken, refreshToken, err := authenticate(email, password, debug)
	if err != nil {
		return nil, err
	}
	if authToken == "" {
		return nil, errors.New("authentication returned empty token")
	}

	if debug {
		fmt.Printf("[DEBUG] Auth token received: %s\n", debugSecret(authToken[:min(20, len(authToken))]+"..."))
	}

	appToken, err := getApplicationToken(authToken, debug)
	if err != nil {
		return nil, err
	}
	if appToken == "" {
		return nil, errors.New("application token request returned empty token")
	}
	return &Session{tokens: Tokens{AuthToken: authToken, AppToken: appToken, RefreshToken: refreshToken}, debug: debug}, nil
}

// Resume continues a session from tokens saved earlier (Session.Tokens), without the
// password. Expired tokens are renewed when the session is used; if that fails, its
// methods return ErrLoginRequired.
func Resume(tokens Tokens) *Session {
	return &Session{tokens: tokens}
}

// Tokens returns the session's current tokens, to save them for Resume. Renewing them
// changes them, so save them again after using the session.
func (s *Session) Tokens() Tokens {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens
}

// UserID returns the account's user ID, which its certificates contain (Expect.UserID).
// After Bikes, it needs no further request.
func (s *Session) UserID() (string, error) {
	s.mu.Lock()
	userID := s.userID
	s.mu.Unlock()
	if userID != "" {
		return userID, nil
	}
	data, err := s.customerData()
	if err != nil {
		return "", err
	}
	return data.Data.UUID, nil
}

// Bikes returns the account's bikes: its own, then the ones shared with it. If it can't
// look up the shared ones, it returns its own along with an error wrapping ErrSharedBikes.
func (s *Session) Bikes() ([]Bike, error) {
	data, err := s.customerData()
	if err != nil {
		return nil, err
	}

	var shared []VehicleAccess
	err = s.call(true, func(t Tokens) error {
		var err error
		shared, err = getSharedVehicles(data.Data.UUID, t.AppToken, s.debug)
		return err
	})
	if err != nil {
		return data.Data.Bikes, fmt.Errorf("%w: %w", ErrSharedBikes, err)
	}
	return addSharedBikes(data.Data.Bikes, shared), nil
}

// RequestCertificate requests a certificate for one of the account's bikes that
// UsesCertificates, for publicKey (a base64 Ed25519 public key, see GenerateED25519), and
// returns it in base64. Check it with CheckCertificate before relying on it.
func (s *Session) RequestCertificate(bike Bike, publicKey string) (string, error) {
	response, err := s.certificateResponse(bike, publicKey)
	if err != nil {
		return "", err
	}

	var data struct {
		Certificate string          `json:"certificate"`
		Err         json.RawMessage `json:"err"`
	}
	if err := json.Unmarshal([]byte(response), &data); err != nil {
		return "", fmt.Errorf("failed to parse certificate response: %w", err)
	}
	if data.Err != nil {
		return "", fmt.Errorf("no certificate: %s", data.Err)
	}
	if data.Certificate == "" {
		return "", errors.New("certificate response missing 'certificate' field")
	}
	return data.Certificate, nil
}

// certificateResponse requests a certificate and returns VanMoof's raw response, which
// the command line tool prints
func (s *Session) certificateResponse(bike Bike, publicKey string) (string, error) {
	var response string
	err := s.call(true, func(t Tokens) error {
		var err error
		response, err = createCertificate(bike.FrameNumber, publicKey, t.AppToken, s.debug)
		return err
	})
	return response, err
}

// customerData fetches the account's customer data, with its user ID and bikes
func (s *Session) customerData() (*CustomerData, error) {
	var data *CustomerData
	err := s.call(false, func(t Tokens) error {
		var err error
		data, err = fetchCustomerData(t.AuthToken, s.debug)
		return err
	})
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.userID = data.Data.UUID
	s.mu.Unlock()
	return data, nil
}

// call runs fn with the session's tokens, renewed first if they've expired (needApp: the
// app token too, else only the auth token), and once more if the server rejects them
func (s *Session) call(needApp bool, fn func(Tokens) error) error {
	t := s.Tokens()
	if isJWTExpired(t.AuthToken) || (needApp && isJWTExpired(t.AppToken)) {
		var err error
		if t, err = s.renew(t, false); err != nil {
			return err
		}
	}

	err := fn(t)
	if !isUnauthorized(err) {
		return err
	}
	if t, err = s.renew(t, !needApp); err != nil {
		return err
	}
	return fn(t)
}

// renew gets a new app token with the auth token, unless that's expired or authRejected,
// and otherwise new auth and app tokens with the refresh token. old are the tokens the
// caller used: if another call renewed them meanwhile, it returns those instead.
func (s *Session) renew(old Tokens, authRejected bool) (Tokens, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokens != old {
		return s.tokens, nil
	}

	t := s.tokens
	if !authRejected && !isJWTExpired(t.AuthToken) {
		if appToken, err := getApplicationToken(t.AuthToken, s.debug); err == nil && appToken != "" {
			t.AppToken = appToken
			s.tokens = t
			return t, nil
		}
	}

	if t.RefreshToken == "" {
		return Tokens{}, ErrLoginRequired
	}
	authToken, refreshToken, err := refreshAuthToken(t.RefreshToken, s.debug)
	if err != nil || authToken == "" {
		return Tokens{}, loginRequired(err)
	}
	appToken, err := getApplicationToken(authToken, s.debug)
	if err != nil || appToken == "" {
		return Tokens{}, loginRequired(err)
	}

	// Keep using the old refresh token unless the server rotated it
	t.AuthToken, t.AppToken = authToken, appToken
	if refreshToken != "" {
		t.RefreshToken = refreshToken
	}
	s.tokens = t
	return t, nil
}

// loginRequired returns ErrLoginRequired, wrapping err with it if there is one
func loginRequired(err error) error {
	if err == nil {
		return ErrLoginRequired
	}
	return fmt.Errorf("%w: %w", ErrLoginRequired, err)
}
