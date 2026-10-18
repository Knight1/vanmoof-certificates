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
