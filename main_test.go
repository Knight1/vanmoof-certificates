package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
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

// The tests never reach VanMoof or the real cache: requests fail and are counted, and the
// home directory is empty
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
	status := run(args)
	os.Stdout, os.Stderr = stdout, stderr
	w.Close()
	return status, <-out
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
