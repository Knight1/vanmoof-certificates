package vanmoof

import (
	"bufio"
	"strings"
	"testing"
)

// setStdin makes the prompts read input, for the duration of the test
func setStdin(t *testing.T, input string) {
	t.Helper()
	old := stdin
	stdin = bufio.NewReader(strings.NewReader(input))
	t.Cleanup(func() { stdin = old })
}

// All prompts read from one reader: separate readers would each buffer the piped input,
// leaving none for the next prompt
func TestReadLineSharedByPrompts(t *testing.T) {
	setStdin(t, "user@example.com\n 1, 2 \n3")
	for _, want := range []string{"user@example.com", "1, 2", "3"} {
		if got, err := ReadLine(); err != nil || got != want {
			t.Errorf("ReadLine() = %q, %v; want %q", got, err, want)
		}
	}
	if _, err := ReadLine(); err == nil {
		t.Error("ReadLine() after the end of the input didn't fail")
	}
}

func frameNumbers(bikes []Bike) string {
	var frames []string
	for _, b := range bikes {
		frames = append(frames, b.FrameNumber)
	}
	return strings.Join(frames, ",")
}

func TestSelectBikes(t *testing.T) {
	bikes := []Bike{
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
	setStdin(t, "1, 42\n")
	var got []Bike
	var err error
	captureStdout(t, func() { got, err = selectBikes(bikes, "ask") })
	if err != nil || frameNumbers(got) != "BBBBBB00001AA" {
		t.Errorf("selectBikes(ask, \"1, 42\") = %q, %v; want BBBBBB00001AA once", frameNumbers(got), err)
	}
}
