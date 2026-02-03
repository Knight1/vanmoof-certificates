package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// parseResetTime parses the x-ratelimit-reset header value (Unix timestamp) into a time.Time
func parseResetTime(reset string) (time.Time, error) {
	timestamp, err := strconv.ParseInt(reset, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(timestamp, 0), nil
}

func doHTTPRequest(method, url string, body io.Reader, headers map[string]string, debug bool) ([]byte, error) {
	if debug {
		fmt.Printf("[DEBUG] %s %s\n", method, url)
		if body != nil {
			if buf, ok := body.(*bytes.Buffer); ok {
				fmt.Printf("[DEBUG] Request body: %s\n", buf.String())
			}
		}
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if debug {
		fmt.Printf("[DEBUG] Response status: %d\n", resp.StatusCode)

		// Display rate limit headers in human-readable format
		if limit := resp.Header.Get("x-ratelimit-limit"); limit != "" {
			fmt.Printf("[DEBUG] Rate Limit: %s requests\n", limit)
		}
		if remaining := resp.Header.Get("x-ratelimit-remaining"); remaining != "" {
			fmt.Printf("[DEBUG] Rate Limit Remaining: %s requests\n", remaining)
		}
		if reset := resp.Header.Get("x-ratelimit-reset"); reset != "" {
			if resetTime, err := parseResetTime(reset); err == nil {
				fmt.Printf("[DEBUG] Rate Limit Reset: %s (in %s)\n",
					resetTime.Format("2006-01-02 15:04:05 MST"),
					time.Until(resetTime).Round(time.Second))
			} else {
				fmt.Printf("[DEBUG] Rate Limit Reset: %s\n", reset)
			}
		}
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if debug {
		fmt.Printf("[DEBUG] Response body length: %d bytes\n", len(respBody))
		fmt.Printf("[DEBUG] Response body: %s\n", string(respBody))
	}

	// Check for HTTP errors
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
