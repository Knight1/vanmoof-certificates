package vanmoof

import "testing"

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
