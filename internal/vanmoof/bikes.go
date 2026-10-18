package vanmoof

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func selectBikes(bikes []BikeData, filter string) ([]BikeData, error) {
	if filter == "all" {
		return bikes, nil
	}

	interactive := filter == "ask"

	if interactive {
		// Display available bikes
		fmt.Println("\nAvailable bikes:")
		for i, bike := range bikes {
			if bike.BikeID != 0 {
				fmt.Printf("%d. %s (ID: %s, Frame: %s)\n", i+1, Redact(bike.Name), RedactID(fmt.Sprint(bike.BikeID)), RedactID(bike.FrameNumber))
			} else {
				fmt.Printf("%d. %s (Frame: %s)\n", i+1, Redact(bike.Name), RedactID(bike.FrameNumber))
			}
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("\nEnter bike numbers to process (comma-separated, or 'all'): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read input: %w", err)
		}
		filter = strings.TrimSpace(input)

		if filter == "all" {
			return bikes, nil
		}
	}

	// Parse comma-separated bike IDs, frame numbers, or indices (interactive only).
	// A bike given more than once, or both by ID and frame number, is selected once.
	var selected []BikeData
	seen := make(map[int]bool)
	add := func(i int) {
		if !seen[i] {
			seen[i] = true
			selected = append(selected, bikes[i])
		}
	}
	parts := strings.Split(filter, ",")

	for _, part := range parts {
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
