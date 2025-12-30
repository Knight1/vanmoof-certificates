package main

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

	if filter == "ask" {
		// Display available bikes
		fmt.Println("\nAvailable SA5 bikes:")
		for i, bike := range bikes {
			fmt.Printf("%d. Bike ID: %d, Frame: %s\n", i+1, bike.BikeID, bike.FrameNumber)
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

	// Parse comma-separated bike IDs or indices
	var selected []BikeData
	parts := strings.Split(filter, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Try to parse as index (1-based)
		var idx int
		if _, err := fmt.Sscanf(part, "%d", &idx); err == nil {
			if idx > 0 && idx <= len(bikes) {
				selected = append(selected, bikes[idx-1])
				continue
			}
		}

		// Try to parse as bike ID
		var bikeID int
		if _, err := fmt.Sscanf(part, "%d", &bikeID); err == nil {
			for _, bike := range bikes {
				if bike.BikeID == bikeID {
					selected = append(selected, bike)
					break
				}
			}
		}
	}

	return selected, nil
}
