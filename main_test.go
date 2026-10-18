package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"

	"github.com/Knight1/vanmoof-certificates/vanmoof"
)

// requests counts the HTTP requests of the tests, which must never reach VanMoof
var requests atomic.Int32

type noNetwork struct{}

func (noNetwork) RoundTrip(r *http.Request) (*http.Response, error) {
	requests.Add(1)
	return nil, fmt.Errorf("the test tried to reach %s", r.URL.Host)
}

// The tests never reach VanMoof or the real cache, and never wait for input: requests fail
// and are counted, the home directory is empty, and standard input is closed
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "vanmoof-main-test-home")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	os.Setenv("HOME", home)
	os.Setenv("USERPROFILE", home)
	os.Unsetenv("VANMOOF_CACHE_KEY")
	os.Unsetenv("VANMOOF_PASSWORD")
	os.Stdin.Close()
	http.DefaultTransport = noNetwork{}
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

// runTool runs the tool with args, and returns its exit status and output (standard
// output and error). It fails the test if the tool tried to reach VanMoof.
func runTool(t *testing.T, args ...string) (int, string) {
	t.Helper()
	before := requests.Load()
	status, out := runOutput(t, args)
	if requests.Load() != before {
		t.Errorf("%q tried to reach VanMoof", args)
	}
	return status, out
}

// runOutput is runTool without failing the test if the tool tried to reach VanMoof
func runOutput(t *testing.T, args []string) (int, string) {
	t.Helper()
	var status int
	out := captureOutput(t, func() { status = run(args) })
	return status, out
}

// captureOutput runs f, and returns what it printed to standard output and error
func captureOutput(t *testing.T, f func()) string {
	t.Helper()
	defer vanmoof.SetRedaction(false, false)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	f()
	os.Stdout, os.Stderr = stdout, stderr
	w.Close()
	return <-out
}

// testCertificate returns a base64 certificate for the frame number and public key, valid
// for a week, with a random signature
func testCertificate(t *testing.T, frame string, publicKey []byte) string {
	t.Helper()
	userID := make([]byte, 16)
	userID[6], userID[8] = 0x40, 0x80 // UUID v4
	payload, err := cbor.Marshal(map[string]any{
		"i": uint64(1), "f": frame, "b": frame, "e": uint64(time.Now().Add(7 * 24 * time.Hour).Unix()),
		"r": uint64(7), "u": userID, "p": publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, ed25519.SignatureSize)
	rand.Read(signature)
	return base64.StdEncoding.EncodeToString(append(signature, payload...))
}

func TestRun(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	pubKey, otherKey := base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(otherPub)
	s6 := testCertificate(t, "AAAAA000001AA", pub)  // no S6 signing key is known, so it can't be verified
	sa5 := testCertificate(t, "BBBBBB00001AA", pub) // a random signature isn't VanMoof's
	const email = "user@example.com"

	tests := []struct {
		name   string
		args   []string
		status int
		output string // part of the output
	}{
		{"version", []string{"-version"}, 0, "vanmoof-certificates version " + vanmoof.Version},
		{"help", []string{"-h"}, 0, "-invitations"},
		{"key pair", []string{"-genkey"}, 0, "Pubkey = "},
		{"key pair, redacted", []string{"-genkey", "-redact"}, 0, "Privkey = [REDACTED]"},
		{"nothing saved yet", []string{"-show-saved", "-email", email}, 0, "Nothing saved"},

		// Certificates, checked offline
		{"S6 certificate", []string{"-cert", s6}, 0, "Certificate valid, but signature not verified"},
		{"for the key", []string{"-cert", s6, "-pubkey", pubKey}, 0, "pubkey ok"},
		{"for the frame number", []string{"-cert", s6, "-framenumber", "AAAAA000001AA"}, 0, "Certificate valid"},
		{"spaces around it", []string{"-cert", " " + s6 + "\n"}, 0, "Certificate valid"},
		{"for another key", []string{"-cert", s6, "-pubkey", otherKey}, 1, "Public key mismatch"},
		{"for another frame number", []string{"-cert", s6, "-framenumber", "AAAAA000002AA"}, 1, "not found in certificate"},
		{"SA5 certificate with a wrong signature", []string{"-cert", sa5}, 1, "Signature INVALID"},
		{"too short", []string{"-cert", "AAAA"}, 1, "certificate is too short"},
		{"-sudo skips the base64 check", []string{"-sudo", "-cert", "not base64!"}, 1, "isn't valid base64"},

		// Invalid flags and values
		{"unknown flag", []string{"-frobnicate"}, 2, "flag provided but not defined"},
		{"-redact with -show-everything", []string{"-debug", "-redact", "-show-everything"}, 2, "cannot be combined"},
		{"-show-everything without -debug", []string{"-show-everything"}, 2, "only works with -debug"},
		{"invalid -show-keys", []string{"-show-keys", "some", "-email", email}, 2, "Invalid -show-keys value"},
		{"invalid -show-keys, escaped", []string{"-show-keys", "\x1b[2J", "-email", email}, 2, `Invalid -show-keys value '\x1b[2J'`},
		{"-show-keys with -cert", []string{"-show-keys", "all", "-cert", s6}, 2, "-show-keys cannot be combined with -cert"},
		{"-new-key with -pubkey", []string{"-new-key", "-pubkey", pubKey, "-email", email}, 2, "-new-key and -pubkey cannot be combined"},
		{"-new-key with -cert", []string{"-new-key", "-cert", s6}, 2, "-new-key only works when requesting certificates"},
		{"-new-key with -show-keys static", []string{"-new-key", "-show-keys", "static", "-email", email}, 2, "-new-key only works"},
		{"-new-key with -show-saved", []string{"-new-key", "-show-saved", "-email", email}, 2, "-new-key only works"},
		{"invalid -invitations", []string{"-invitations", "maybe", "-email", email}, 2, "Invalid -invitations value"},
		{"-invitations list with a selection", []string{"-invitations", "list=1", "-email", email}, 2, "only to accept or decline"},
		{"-invitations with an empty selection", []string{"-invitations", "accept=", "-email", email}, 2, "only to accept or decline"},
		{"-invitations with -show-keys", []string{"-invitations", "list", "-show-keys", "all", "-email", email}, 2, "-invitations cannot be combined"},
		{"-cleartext-keys with -no-cache", []string{"-cleartext-keys", "-no-cache", "-email", email}, 2, "-cleartext-keys and -no-cache cannot be combined"},
		{"-show-saved with -no-cache", []string{"-show-saved", "-no-cache", "-email", email}, 2, "-show-saved cannot be combined"},
		{"invalid certificate", []string{"-cert", "not base64!"}, 2, "Invalid base64 certificate string"},
		{"invalid public key", []string{"-pubkey", "AAAA", "-email", email}, 2, "Invalid Ed25519 public key"},
		{"-framenumber without -cert", []string{"-framenumber", "AAAAA000001AA", "-email", email}, 2, "-framenumber only works with -cert"},
		{"invalid frame number", []string{"-cert", s6, "-framenumber", "nope"}, 2, "Invalid frame number"},
		{"empty bike ID", []string{"-bikes", "1,,2", "-email", email}, 2, "Empty bike ID"},
		{"invalid bike ID", []string{"-bikes", "1,x!", "-email", email}, 2, "Invalid bike ID"},
		{"email address with a name", []string{"-email", "User <user@example.com>"}, 2, "Invalid email address"},

		// Asking for the email address fails, as standard input is closed
		{"no email address", nil, 1, "Enter VanMoof email: Error reading email"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, out := runTool(t, tt.args...)
			if status != tt.status || !strings.Contains(out, tt.output) {
				t.Errorf("run(%q) = %d, want %d with %q:\n%s", tt.args, status, tt.status, tt.output, out)
			}
		})
	}
}

// -genkey prints a matching key pair: a 64 byte private and a 32 byte public key
func TestRunGenkey(t *testing.T) {
	_, out := runTool(t, "-genkey")
	m := regexp.MustCompile(`Privkey = (\S+)\nPubkey = (\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("output: %q", out)
	}
	priv, err1 := base64.StdEncoding.DecodeString(m[1])
	pub, err2 := base64.StdEncoding.DecodeString(m[2])
	if err1 != nil || err2 != nil || len(priv) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.PrivateKey(priv).Public().(ed25519.PublicKey), pub) {
		t.Errorf("not a key pair: %q", out)
	}
}

// broken fails to read or write anything
type broken struct{}

func (broken) Read([]byte) (int, error)  { return 0, errors.New("broken") }
func (broken) Write([]byte) (int, error) { return 0, errors.New("broken") }

// Without randomness there's no key pair
func TestRunGenkeyFails(t *testing.T) {
	random := rand.Reader
	rand.Reader = broken{}
	defer func() { rand.Reader = random }()
	if status, out := runTool(t, "-genkey"); status != 1 || !strings.Contains(out, "Error: failed to generate key pair: broken") {
		t.Errorf("status %d:\n%s", status, out)
	}
}

// main exits with the status of the run
func TestMainExits(t *testing.T) {
	status := -1
	args := os.Args
	exit, os.Args = func(code int) { status = code }, []string{"vanmoof-certificates", "-frobnicate"}
	t.Cleanup(func() { exit, os.Args = os.Exit, args })
	if out := captureOutput(t, main); status != exitUsage || !strings.Contains(out, "flag provided but not defined") {
		t.Errorf("main exited with %d:\n%s", status, out)
	}
}

// A cache that -show-saved can't read is an error
func TestRunShowSavedUnreadable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".vanmoof-certificates")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bikes.json"), []byte("not JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if status, out := runTool(t, "-show-saved", "-email", "user@example.com"); status != 1 || !strings.Contains(out, "Error: ") {
		t.Errorf("status %d:\n%s", status, out)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fakeVanMoof answers like VanMoof for an account without bikes and invitations, for the
// rest of the test, so the flows that log in run to their end
func fakeVanMoof(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("VANMOOF_PASSWORD", "password")
	claims := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"exp":%d}`, time.Now().Add(time.Hour).Unix()))
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." + claims + ".c2lnbmF0dXJl"
	const userID = "00000000-0000-4000-8000-000000000001"
	responses := map[string]string{
		"/v8/authenticate":                         `{"token":"` + token + `","refreshToken":"refresh"}`,
		"/v8/getApplicationToken":                  `{"token":"` + token + `"}`,
		"/v8/getCustomerData":                      `{"data":{"uuid":"` + userID + `","bikes":[],"bikeDetails":[]}}`,
		"/v8/getBikeSharingInvitations":            `{"invitations":[]}`,
		"/external/riders/" + userID + "/vehicles": `{"vehicle_access":[]}`,
	}
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, ok := responses[r.URL.Path]
		status := http.StatusOK
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = noNetwork{} })
}

// The flows that log in exit with 0 when they're done, and 1 when they fail: here without a
// password, as standard input is closed
func TestRunLogsIn(t *testing.T) {
	const email = "user@example.com"
	tests := []struct {
		name   string
		args   []string
		output string // part of the output
	}{
		{"certificates", []string{"-email", email}, "No supported bikes found"},
		{"BLE keys", []string{"-show-keys", "static", "-email", email}, "No static bikes found"},
		{"invitations", []string{"-invitations", "list", "-email", email}, "No pending bike sharing invitations"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeVanMoof(t)
			if status, out := runTool(t, tt.args...); status != 0 || !strings.Contains(out, tt.output) {
				t.Errorf("run(%q) = %d, want 0 with %q:\n%s", tt.args, status, tt.output, out)
			}
		})
	}

	t.Setenv("VANMOOF_PASSWORD", "")
	if status, out := runTool(t, "-show-keys", "static", "-email", email); status != 1 || !strings.Contains(out, "Error: authentication failed: error reading password") {
		t.Errorf("without a password: status %d:\n%s", status, out)
	}
}

// The flag package's output reaches the terminal with control characters, bidi overrides and
// invalid UTF-8 escaped, but line breaks and tabs as they are
func TestEscaped(t *testing.T) {
	const in = "-\x1b[2J\xe2\x80\xae\xff\tusage\n"
	want := "-" + `\x1b` + "[2J" + `\u` + "202e" + string(utf8.RuneError) + "\tusage\n"
	var b strings.Builder
	if n, err := (escaped{&b}).Write([]byte(in)); n != len(in) || err != nil || b.String() != want {
		t.Errorf("Write = %d, %v, wrote %q; want %d, %q", n, err, b.String(), len(in), want)
	}
	if n, err := (escaped{broken{}}).Write([]byte(in)); n != 0 || err == nil {
		t.Errorf("Write to a broken writer = %d, %v", n, err)
	}
}

// The debug line with the flags hides their values with -redact
func TestRunDebugFlagsRedacted(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	pubKey := base64.StdEncoding.EncodeToString(pub)
	_, out := runTool(t, "-debug", "-redact", "-pubkey", pubKey, "-email", "LeakyUser", "-bikes", "LEAKY12345ZZ", "-invitations", "decline=1eaf0000-0000-3000-8000-0000000000cc")
	if !strings.Contains(out, "[DEBUG] Flags:") {
		t.Fatalf("no debug line: %q", out)
	}
	for _, s := range []string{pubKey, "LeakyUser", "LEAKY12345ZZ", "1eaf0000-0000-3000-8000-0000000000cc"} {
		if strings.Contains(out, s) {
			t.Errorf("output contains %q:\n%s", s, out)
		}
	}
}

// unescaped reports whether output has invalid UTF-8, a bidi override, or a control
// character other than a line break or a tab (the usage has tabs)
func unescaped(output string) bool {
	return !utf8.ValidString(output) || strings.ContainsFunc(output, func(r rune) bool {
		return r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r))
	})
}

// Whatever the command line, the tool exits with 0, 1 or 2 without a panic, and its output
// has nothing for a terminal to interpret. It never waits for input: the email address is
// given, and the password set. What needs VanMoof fails, as requests do here.
func FuzzRun(f *testing.F) {
	for _, line := range []string{"-version", "-h", "-genkey -redact", "-cert AAAA", "-show-keys maybe", "-invitations accept=1,2",
		"-bikes 1,,2", "-debug -redact -show-everything", "-show-saved", "-cert \x1b[2J", "-show-keys \x1b[2J -debug",
		"-framenumber BBBBBB00001AA -cert QUFB", "-sudo -cert garbage", "-debug -bikes LEAKY12345ZZ", "-new-key -pubkey x",
		"-cleartext-keys -no-cache", "--", "-email= -debug", "-bikes ask -debug", "-invitations decline=\xe2\x80\xae"} {
		f.Add(line)
	}
	f.Fuzz(func(t *testing.T, line string) {
		t.Setenv("VANMOOF_PASSWORD", "password")
		args := []string{"-email", "fuzz@example.com"}
		for arg := range strings.SplitSeq(line, " ") {
			if name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "="); strings.HasPrefix(arg, "-") && name == "email" {
				continue // without one it would ask
			}
			args = append(args, arg)
		}
		status, out := runOutput(t, args)
		if status < 0 || status > 2 {
			t.Errorf("run(%q) = %d", args, status)
		}
		if unescaped(out) {
			t.Errorf("run(%q) output not escaped: %q", args, out)
		}
	})
}
