package vanmoof

import (
	"os"
	"strings"
	"testing"
)

func frameNumbers(bikes []BikeData) string {
	var frames []string
	for _, b := range bikes {
		frames = append(frames, b.FrameNumber)
	}
	return strings.Join(frames, ",")
}

func TestSelectBikes(t *testing.T) {
	bikes := []BikeData{
		{BikeID: 42, FrameNumber: "BBBBBB00001AA"},
		{BikeID: 43, FrameNumber: "BBBBBB00002AA"},
		{FrameNumber: "AAAAA000001AA"}, // shared, so no numeric ID
	}
	tests := []struct {
		filter string
		want   string
	}{
		{"42", "BBBBBB00001AA"},
		{"42,42", "BBBBBB00001AA"},
		{"42, BBBBBB00001AA", "BBBBBB00001AA"}, // the same bike by ID and frame number
		{"43,AAAAA000001AA", "BBBBBB00002AA,AAAAA000001AA"},
		{"42abc", ""}, // not read as bike 42
		{"0", ""},     // not every bike without an ID
	}
	for _, tt := range tests {
		got, err := selectBikes(bikes, tt.filter)
		if err != nil || frameNumbers(got) != tt.want {
			t.Errorf("selectBikes(%q) = %q, %v; want %q", tt.filter, frameNumbers(got), err, tt.want)
		}
	}

	// Interactively, numbers are list positions first: "1" and "42" are the same bike here
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString("1, 42\n")
	w.Close()
	stdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = stdin })

	var got []BikeData
	captureStdout(t, func() { got, err = selectBikes(bikes, "ask") })
	if err != nil || frameNumbers(got) != "BBBBBB00001AA" {
		t.Errorf("selectBikes(ask, \"1, 42\") = %q, %v; want BBBBBB00001AA once", frameNumbers(got), err)
	}
}
