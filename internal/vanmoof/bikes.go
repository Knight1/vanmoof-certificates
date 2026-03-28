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
		fmt.Println("\nAvailable SA5 bikes:")
		for i, bike := range bikes {
			if bike.BikeID != 0 {
				fmt.Printf("%d. %s (ID: %d, Frame: %s)\n", i+1, bike.Name, bike.BikeID, bike.FrameNumber)
			} else {
				fmt.Printf("%d. %s (Frame: %s)\n", i+1, bike.Name, bike.FrameNumber)
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

	// Parse comma-separated bike IDs, frame numbers, or indices (interactive only)
	var selected []BikeData
	parts := strings.Split(filter, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)

		var numericID int
		isNumeric := false
		if _, err := fmt.Sscanf(part, "%d", &numericID); err == nil {
			isNumeric = true
		}

		if isNumeric && interactive {
			// In interactive mode, treat as 1-based list index
			if numericID > 0 && numericID <= len(bikes) {
				selected = append(selected, bikes[numericID-1])
				continue
			}
		}

		if isNumeric {
			// Match by bike API ID
			for _, bike := range bikes {
				if bike.BikeID == numericID {
					selected = append(selected, bike)
					break
				}
			}
		} else {
			// Match by frame number (for shared bikes)
			for _, bike := range bikes {
				if bike.FrameNumber == part {
					selected = append(selected, bike)
					break
				}
			}
		}
	}

	return selected, nil
}
