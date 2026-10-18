package vanmoof

import "testing"

func TestIsS6Certificate(t *testing.T) {
	s6Bike := BikeData{FrameNumber: "AAAAA000000AA", BleProfile: "ELECTRIFIED_2025"}
	sa5Bike := BikeData{FrameNumber: "BBBBBB00000AA", BleProfile: "ELECTRIFIED_2022"}

	tests := []struct {
		name string
		r    certResult
		want bool
	}{
		{"matched S6 bike", certResult{matchedBike: &s6Bike}, true},
		{"matched non-S6 bike, non-S6-shaped frame ID", certResult{matchedBike: &sa5Bike, frameID: []byte("BBBBBB00000AA")}, false},
		{"no matched bike, S6-shaped frame ID", certResult{frameID: []byte("AAAAA000000AA")}, true},
		{"no matched bike, SA5-shaped frame ID", certResult{frameID: []byte("BBBBBB00000AA")}, false},
		{"no matched bike, empty frame ID", certResult{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isS6Certificate(tt.r); got != tt.want {
				t.Errorf("isS6Certificate() = %v, want %v", got, tt.want)
			}
		})
	}
}
