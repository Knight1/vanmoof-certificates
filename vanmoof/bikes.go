package vanmoof

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// stdin is shared by every prompt: with piped input, a reader per prompt would buffer
// the lines meant for the next one, which would then find the input already used up.
var stdin = bufio.NewReader(os.Stdin)

// ReadLine reads a line from standard input, without the spaces around it
func ReadLine() (string, error) {
	line, err := stdin.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// Model returns the bike's model, such as "S5", "S3" or "S6", or its BLE profile if it's
// one this package doesn't know. A profile shared by two frame shapes, such as the
// S3/X3's or the S5/A5's, gives the one of the bike's FrameShape, or both ("S3/X3",
// "SA5") without it.
func (b Bike) Model() string {
	return bikeModel(b.BleProfile, b.FrameShape)
}

// FindMy reports whether the bike works with Apple's Find My, and whether that's known:
// for an S3/X3 it is, by its BLE profile, and the SA5 and later always do, but it isn't
// known for every model
func (b Bike) FindMy() (supported, known bool) {
	supported, known = bleProfileFindMy[b.BleProfile]
	return supported, known
}

// bikeModel is Bike.Model of a bike with the BLE profile and frame shape
func bikeModel(bleProfile, frameShape string) string {
	model := bleProfileModel[bleProfile]
	if model == "" {
		return bleProfile
	}
	shape := strings.ToUpper(frameShape)
	if m := shapesModelRegexp.FindStringSubmatch(model); m != nil && len(shape) == 1 && strings.Contains(m[1], shape) {
		return shape + m[2]
	}
	switch shape {
	case "S":
		return sModelRegexp.ReplaceAllString(model, "")
	case "X":
		return xModelRegexp.ReplaceAllString(model, "")
	}
	return model
}

// modelDescription is the model for output, "unknown" if the BLE profile isn't one this
// package knows, with whether it works with Find My if that's known: e.g. "S3, no Find My"
func modelDescription(bleProfile, frameShape string) string {
	model := "unknown"
	if bleProfileModel[bleProfile] != "" {
		model = bikeModel(bleProfile, frameShape)
	}
	if note := findMyNote(bleProfile); note != "" {
		model += ", " + note
	}
	return model
}

// findMyNote says whether bikes of the BLE profile work with Find My, "" if not known
func findMyNote(bleProfile string) string {
	supported, known := Bike{BleProfile: bleProfile}.FindMy()
	switch {
	case !known:
		return ""
	case supported:
		return "Find My"
	}
	return "no Find My"
}

// findMySuffix is findMyNote in parentheses after a model, e.g. " (Find My)"
func findMySuffix(bleProfile string) string {
	if note := findMyNote(bleProfile); note != "" {
		return " (" + note + ")"
	}
	return ""
}

// UsesCertificates reports whether the bike is unlocked with certificates (S5/A5 and S6),
// which Session.RequestCertificate is for. Older bikes use a BLE key instead.
func (b Bike) UsesCertificates() bool {
	return isCertOnlyProfile(b.BleProfile)
}

// sharedWithAccount reports whether getCustomerData gave the bike as shared with the
// account rather than its own: with a role other than owner
func (b Bike) sharedWithAccount() bool {
	return b.CustomerRole != "" && !strings.EqualFold(b.CustomerRole, "owner")
}

// displayName is the bike's name for output: for a shared bike, with its owner's name
func displayName(b Bike) string {
	if b.Owner != "" {
		return b.Name + " (shared by " + b.Owner + ")"
	}
	return b.Name
}

func selectBikes(bikes []Bike, filter string) ([]Bike, error) {
	if filter == "all" {
		return bikes, nil
	}

	interactive := filter == "ask"

	if interactive {
		// Display available bikes
		fmt.Println("\nAvailable bikes:")
		for i, bike := range bikes {
			if bike.BikeID != 0 {
				fmt.Printf("%d. %s (ID: %s, Frame: %s)\n", i+1, Redact(displayName(bike)), RedactID(fmt.Sprint(bike.BikeID)), RedactID(bike.FrameNumber))
			} else {
				fmt.Printf("%d. %s (Frame: %s)\n", i+1, Redact(displayName(bike)), RedactID(bike.FrameNumber))
			}
		}

		fmt.Print("\nEnter bike numbers to process (comma-separated, or 'all'): ")
		input, err := ReadLine()
		if err != nil {
			return nil, fmt.Errorf("failed to read input: %w", err)
		}
		filter = input

		if filter == "all" {
			return bikes, nil
		}
	}

	// Parse comma-separated bike IDs, frame numbers, or indices (interactive only).
	// A bike given more than once, or both by ID and frame number, is selected once.
	var selected []Bike
	seen := make(map[int]bool)
	add := func(i int) {
		if !seen[i] {
			seen[i] = true
			selected = append(selected, bikes[i])
		}
	}

	for part := range strings.SplitSeq(filter, ",") {
		part = strings.TrimSpace(part)

		numericID, isNumeric := ParseBikeID(part)

		if isNumeric && interactive {
			// In interactive mode, treat as 1-based list index
			if numericID > 0 && numericID <= len(bikes) {
				add(numericID - 1)
				continue
			}
		}

		if isNumeric {
			// Match by bike API ID. 0 is never a real bike ID — it's the zero value
			// shared/guest bikes get when merged in (they have no numeric ID), so
			// treat it as "no match" rather than matching every shared bike.
			if numericID != 0 {
				for i, bike := range bikes {
					if bike.BikeID == numericID {
						add(i)
						break
					}
				}
			}
		} else {
			// Match by frame number (for shared bikes)
			for i, bike := range bikes {
				if bike.FrameNumber == part {
					add(i)
					break
				}
			}
		}
	}

	return selected, nil
}
