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

// Model returns the bike's model, such as "SA5" or "S6", or its BLE profile if it's one
// this package doesn't know
func (b Bike) Model() string {
	if model := bleProfileModel[b.BleProfile]; model != "" {
		return model
	}
	return b.BleProfile
}

// UsesCertificates reports whether the bike is unlocked with certificates (S5/A5 and S6),
// which Session.RequestCertificate is for. Older bikes use a BLE key instead.
func (b Bike) UsesCertificates() bool {
	return isCertOnlyProfile(b.BleProfile)
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
