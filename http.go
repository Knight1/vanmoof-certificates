package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

func doHTTPRequest(method, url string, body io.Reader, headers map[string]string, debug bool) ([]byte, error) {
	if debug {
		fmt.Printf("[DEBUG] %s %s\n", method, url)
		if body != nil {
			if buf, ok := body.(*bytes.Buffer); ok {
				fmt.Printf("[DEBUG] Request body: %s\n", buf.String())
			}
		}
	}

	client := &http.Client{}
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
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if debug {
		if len(respBody) > 200 {
			fmt.Printf("[DEBUG] Response body length: %d bytes\n", len(respBody))
		} else {
			fmt.Printf("[DEBUG] Response body: %s\n", string(respBody))
		}
	}

	// Check for HTTP errors
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
