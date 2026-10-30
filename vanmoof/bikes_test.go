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

// A bike's model is the one of its frame shape, both without it, and whether it works with
// Find My is known for the S3/X3 and older
func TestBikeModel(t *testing.T) {
	tests := []struct {
		profile, shape, model     string
		usesCertificates          bool
		findMy, findMyKnown       bool
		description, findMySuffix string
	}{
		{"ELECTRIFIED_2022", "S", "SA5", true, false, false, "SA5", ""},
		{"ELECTRIFIED_2025", "", "S6", true, false, false, "S6", ""},
		{"ELECTRIFIED_2023_TRACK1", "", "S4/X4", false, false, false, "S4/X4", ""},
		{"ELECTRIFIED_2023_TRACK_1", "x", "X4", false, false, false, "X4", ""},
		{"ELECTRIFIED_2021", "S", "S3", false, true, true, "S3, Find My", " (Find My)"},
		{"ELECTRIFIED_2021", "X", "X3", false, true, true, "X3, Find My", " (Find My)"},
		{"ELECTRIFIED_2021", "", "S3/X3", false, true, true, "S3/X3, Find My", " (Find My)"},
		{"ELECTRIFIED_2020", "S", "S3", false, false, true, "S3, no Find My", " (no Find My)"},
		{"ELECTRIFIED_2020", "A", "S3/X3", false, false, true, "S3/X3, no Find My", " (no Find My)"}, // a shape it doesn't come in
		{"ELECTRIFIED_2018", "X", "X2", false, false, true, "X2, no Find My", " (no Find My)"},
		{"ELECTRIFIED_2016", "S", "S", false, false, true, "S, no Find My", " (no Find My)"},
		{"SMARTBIKE_2018", "X", "Smart X", false, false, true, "Smart X, no Find My", " (no Find My)"},
		{"SMARTBIKE_2018", "S", "Smart S", false, false, true, "Smart S, no Find My", " (no Find My)"},
		{"ELECTRIFIED_2099", "S", "ELECTRIFIED_2099", false, false, false, "unknown", ""}, // unknown: shown as it is
		{"", "", "", false, false, false, "unknown", ""},
	}
	for _, tt := range tests {
		b := Bike{BleProfile: tt.profile, FrameShape: tt.shape}
		if b.Model() != tt.model || b.UsesCertificates() != tt.usesCertificates {
			t.Errorf("%q %q: model %q, uses certificates %v", tt.profile, tt.shape, b.Model(), b.UsesCertificates())
		}
		if findMy, known := b.FindMy(); findMy != tt.findMy || known != tt.findMyKnown {
			t.Errorf("%q: FindMy() = %v, %v; want %v, %v", tt.profile, findMy, known, tt.findMy, tt.findMyKnown)
		}
		if got := modelDescription(tt.profile, tt.shape); got != tt.description {
			t.Errorf("modelDescription(%q, %q) = %q, want %q", tt.profile, tt.shape, got, tt.description)
		}
		if got := findMySuffix(tt.profile); got != tt.findMySuffix {
			t.Errorf("findMySuffix(%q) = %q, want %q", tt.profile, got, tt.findMySuffix)
		}
		if inv := (Invitation{BleProfile: tt.profile, FrameShape: tt.shape}); inv.Model() != tt.model {
			t.Errorf("%q %q: invitation model %q", tt.profile, tt.shape, inv.Model())
		}
	}
}
