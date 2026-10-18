package vanmoof

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"
)

// Output redaction, set once from the command line with SetRedaction:
//   - by default, debug output hides secrets such as tokens and BLE keys
//   - -redact hides secrets and personal data in all output, so it can be shared
//   - -show-everything hides nothing, for debugging locally
var (
	redactOutput   bool
	showEverything bool
)

const redacted = "[REDACTED]"

// SetRedaction sets what the output hides: with redact, secrets and personal data
// everywhere, with everything, nothing at all (not even in debug output).
func SetRedaction(redact, everything bool) {
	redactOutput, showEverything = redact, everything
}

// Redact hides s with -redact: a secret the regular output shows on purpose (such as a
// private key or BLE key), or personal data (such as a name or email address).
func Redact(s string) string {
	if redactOutput && s != "" {
		return redacted
	}
	return s
}

// RedactID hides an identifier, such as a frame number or bike ID, with -redact. Only
// its shape is kept (letters as L, digits as D), which is enough to debug its format.
func RedactID(s string) string {
	if !redactOutput {
		return s
	}
	return idShape(s)
}

func idShape(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case unicode.IsLetter(r):
			return 'L'
		case unicode.IsDigit(r):
			return 'D'
		}
		return r
	}, s)
}

// debugSecret hides a secret, such as a token, in debug output unless -show-everything
func debugSecret(s string) string {
	if (redactOutput || !showEverything) && s != "" {
		return redacted
	}
	return s
}

var (
	// scrubPatterns match secrets and personal data in free text
	scrubPatterns = []*regexp.Regexp{
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`),                    // JWT
		regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`), // UUID
		regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),                       // email address
		regexp.MustCompile(`(?i)\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b`),                                 // MAC address
		regexp.MustCompile(`(?i)\b[0-9a-f]{32,}\b`),                                                // hex key
		regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`),                                             // base64 key or certificate
	}
	// idPattern matches frame numbers and bike IDs in free text
	idPattern = regexp.MustCompile(`\b[A-Za-z]{0,6}\d{5,}[A-Za-z]{0,2}\b`)
)

// ScrubText hides secrets and personal data in free text, such as an error message or
// URL, with -redact: the home directory, tokens, keys, UUIDs, email and MAC addresses,
// and (keeping their shape) frame numbers and IDs.
func ScrubText(s string) string {
	if !redactOutput {
		return s
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		s = strings.ReplaceAll(s, home, "~")
	}
	for _, p := range scrubPatterns {
		s = p.ReplaceAllString(s, redacted)
	}
	return idPattern.ReplaceAllStringFunc(s, idShape)
}

var (
	// harmlessFields are kept even with -redact: they're needed to debug, and identify nobody
	harmlessFields = map[string]bool{
		"bleprofile": true, "ble_profile": true, "messagesviable": true, "role": true, "sku": true,
		"status": true, "code": true,
		"alg": true, "typ": true, "kid": true, "exp": true, "iat": true, "nbf": true, "iss": true, "aud": true, // JWT
	}
	// messageFields hold error messages, kept with -redact apart from personal data in them
	messageFields = map[string]bool{"err": true, "error": true, "message": true}
	// idFields hold identifiers, of which -redact keeps only the shape
	idFields = map[string]bool{
		"id": true, "bikeid": true, "bike_id": true, "vehicle_id": true,
		"framenumber": true, "frameserial": true, "mainecuserial": true,
	}
)

// isSecretField reports whether a JSON field (lower case) holds a credential or key,
// such as a token, a BLE key, or a bike's key object or messages.
func isSecretField(key string) bool {
	if key == "key" || key == "content" || (strings.HasSuffix(key, "key") && !strings.Contains(key, "public")) {
		return true
	}
	for _, s := range []string{"token", "secret", "password", "passcode"} {
		if strings.Contains(key, s) {
			return true
		}
	}
	return false
}

// redactJSON redacts a JSON document, such as an HTTP body: secret fields unless
// -show-everything, and with -redact every field that isn't known to be harmless
// (identifiers keep their shape). Anything that isn't JSON goes through ScrubText.
func redactJSON(doc string) string {
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	var v interface{}
	if !json.Valid([]byte(doc)) || dec.Decode(&v) != nil {
		return ScrubText(doc)
	}
	v, changed := redactValue(v, "", false)
	if !changed {
		return doc
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return redacted
	}
	return strings.TrimSuffix(out.String(), "\n")
}

// redactValue redacts the decoded JSON value v of field key (lower case), recursively.
// inSecret is set within a secret field. It reports whether it hid anything.
func redactValue(v interface{}, key string, inSecret bool) (interface{}, bool) {
	inSecret = inSecret || isSecretField(key)
	changed := false
	switch val := v.(type) {
	case map[string]interface{}:
		for k, fv := range val {
			nv, c := redactValue(fv, strings.ToLower(k), inSecret)
			val[k], changed = nv, changed || c
		}
		return val, changed
	case []interface{}:
		for i, ev := range val {
			nv, c := redactValue(ev, key, inSecret)
			val[i], changed = nv, changed || c
		}
		return val, changed
	case nil, bool:
		return v, false
	}

	s := fmt.Sprint(v)
	var out string
	switch {
	case s == "":
		return v, false
	case inSecret:
		out = debugSecret(s)
	case !redactOutput || harmlessFields[key]:
		return v, false
	case messageFields[key]:
		out = ScrubText(s)
	case idFields[key]:
		out = idShape(s)
	default:
		out = redacted
	}
	if out == s {
		return v, false
	}
	return out, true
}
