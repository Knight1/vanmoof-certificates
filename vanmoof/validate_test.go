package vanmoof

import (
	"encoding/base64"
	"testing"
)

func TestLooksLikeFrameNumber(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"BBBBBB00001AA", true}, // SA5: 6 letters + 5 digits + 2 letters
		{"AAAAA000001AA", true}, // S6 (and some SA5s): 5 letters + 6 digits + 2 letters
		{"ASY0000000", true},    // older bikes: 3 letters + 7 digits
		{"", false},
		{"asy0000000", false},
		{"ASY 0000000", false},
		{"ASY-0000000", false},
		{"0000000ASY", false},
	}
	for _, tt := range tests {
		if got := LooksLikeFrameNumber(tt.s); got != tt.want {
			t.Errorf("LooksLikeFrameNumber(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}

	// ValidateFrameNumber stays strict: certificates and -framenumber are SA5/S6 only
	if ValidateFrameNumber("ASY0000000") {
		t.Error("ValidateFrameNumber accepts a pre-S5 frame number")
	}
}

func TestParseBikeID(t *testing.T) {
	tests := []struct {
		s    string
		id   int
		isID bool
	}{
		{"186000", 186000, true},
		{"0", 0, true},
		{"2147483647", 2147483647, true},
		{"2147483648", 0, false},
		{"123abc", 0, false},
		{"BBBBBB00001AA", 0, false},
		{"-5", 0, false},
		{"+5", 0, false},
		{" 5", 0, false},
		{"", 0, false},
	}
	for _, tt := range tests {
		if id, ok := ParseBikeID(tt.s); ok != tt.isID || (ok && id != tt.id) {
			t.Errorf("ParseBikeID(%q) = %d, %v; want %d, %v", tt.s, id, ok, tt.id, tt.isID)
		}
	}
}

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		email string
		want  bool
	}{
		{"user@example.com", true},
		{"Name <user@example.com>", false},
		{"user@example.com (comment)", false},
		{" user@example.com", false},
		{"user", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsValidEmail(tt.email); got != tt.want {
			t.Errorf("IsValidEmail(%q) = %v, want %v", tt.email, got, tt.want)
		}
	}
}

func TestValidateUUID(t *testing.T) {
	for version := range 16 {
		uuid := make([]byte, 16)
		uuid[6], uuid[8] = byte(version<<4), 0x80 // the variant of RFC 9562 (10xx)
		if got, want := validateUUID(uuid), version >= 1 && version <= 8; got != want {
			t.Errorf("version %d: validateUUID = %v, want %v", version, got, want)
		}
	}

	uuid := make([]byte, 16)
	uuid[6], uuid[8] = 0x40, 0xc0 // Microsoft's variant (110x)
	if validateUUID(uuid) {
		t.Error("validateUUID accepts another variant")
	}
	if validateUUID(make([]byte, 15)) {
		t.Error("validateUUID accepts 15 bytes")
	}
}

func TestIsValidPublicKey(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	key := make([]byte, 32)
	tests := []struct {
		s                 string
		base64, publicKey bool
	}{
		{"", false, false},
		{"not base64!", false, false},
		{"AAAA", true, false},
		{b64(key), true, true},
		{b64(append([]byte{0}, key...)), true, true}, // with a 0x00 prefix
		{b64(append([]byte{1}, key...)), true, false},
		{b64(key[:31]), true, false},
		{" " + b64(key), false, false},                            // main trims it first
		{base64.RawStdEncoding.EncodeToString(key), false, false}, // without padding
	}
	for _, tt := range tests {
		if IsValidBase64(tt.s) != tt.base64 || IsValidEd25519PublicKey(tt.s) != tt.publicKey {
			t.Errorf("%q: base64 %v, public key %v; want %v, %v", tt.s, IsValidBase64(tt.s), IsValidEd25519PublicKey(tt.s), tt.base64, tt.publicKey)
		}
	}
}
