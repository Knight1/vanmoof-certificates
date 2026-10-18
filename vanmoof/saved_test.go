package vanmoof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The tests never reach the network or the real cache, and never wait for input: a request
// fails unless the test answers it (fakeVanMoof, newRevocationServers), they start with an
// empty home directory, without VANMOOF_CACHE_KEY and VANMOOF_PASSWORD, and with standard
// input closed (setStdin and typePassword give the prompts their input)
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "vanmoof-test-home")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	os.Setenv("HOME", home)
	os.Setenv("USERPROFILE", home)
	os.Unsetenv("VANMOOF_CACHE_KEY")
	os.Unsetenv("VANMOOF_PASSWORD")
	os.Stdin.Close()
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("the test tried to reach %s", r.URL.Host)
	})
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

// getCert runs GetCert against the fake VanMoof, and returns its output
func getCert(t *testing.T, opts Options) string {
	t.Helper()
	var err error
	out := captureStdout(t, func() { err = GetCert(leakEmail, opts) })
	if err != nil {
		t.Fatalf("GetCert: %v\n%s", err, out)
	}
	return out
}

// printedPrivateKey returns the private key in the output, if any
func printedPrivateKey(out string) string {
	if m := privKeyLine.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

func savedBikeOf(account savedAccount, frameNumber string) *savedBike {
	for i := range account.Bikes {
		if account.Bikes[i].FrameNumber == frameNumber {
			return &account.Bikes[i]
		}
	}
	return nil
}

// A run saves the key pair, the certificates, the BLE keys and the customer data, and the
// next run requests its certificates for the same key pair, until -new-key replaces it.
// The cache is unencrypted here, see TestCacheEncrypted.
func TestCacheSavesEverything(t *testing.T) {
	useTempCache(t, "")
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	_, pubKeys := fakeVanMoof(t)

	key := printedPrivateKey(getCert(t, Options{BikeFilter: "all", CleartextKeys: true}))
	account, _ := bikeCache.load(leakEmail, false)
	if account.Key == nil || key == "" || account.Key.PrivateKey != key {
		t.Fatalf("printed private key %q, saved key pair %+v", key, account.Key)
	}
	for _, frame := range []string{leakSA5Frame, leakS6Frame} {
		b := savedBikeOf(account, frame)
		if b == nil || b.Certificate == "" || b.PrivateKey != key || b.PublicKey != account.Key.PublicKey || !b.Expires.After(time.Now()) {
			t.Errorf("%s: saved %+v", frame, b)
		}
	}
	if b := savedBikeOf(account, leakS3Frame); b == nil || b.BLEKey != leakBLEKey || b.Model != "S3/X3" {
		t.Errorf("S3: saved %+v", b)
	}
	if data, ok := customerDataCache.load(leakEmail, false); !ok || !bytes.Contains(data, []byte(leakName)) {
		t.Errorf("customer data not saved: %s", data)
	}

	// The next run uses the saved key pair
	requested := len(*pubKeys)
	out := getCert(t, Options{BikeFilter: "all", CleartextKeys: true})
	if !strings.Contains(out, "Using the saved key pair") || printedPrivateKey(out) != key {
		t.Errorf("saved key pair not used:\n%s", out)
	}
	for _, pub := range (*pubKeys)[requested:] {
		if pub != account.Key.PublicKey {
			t.Errorf("certificate requested for %s, not the saved key pair's %s", pub, account.Key.PublicKey)
		}
	}

	// -new-key makes a new key pair, which replaces the saved one along with the certificates
	newKey := printedPrivateKey(getCert(t, Options{BikeFilter: "all", NewKey: true, CleartextKeys: true}))
	account, _ = bikeCache.load(leakEmail, false)
	if newKey == "" || newKey == key || account.Key.PrivateKey != newKey {
		t.Errorf("-new-key: printed %q, saved %+v", newKey, account.Key)
	}
	if b := savedBikeOf(account, leakSA5Frame); b == nil || b.PrivateKey != newKey {
		t.Errorf("certificate for the new key pair not saved: %+v", b)
	}

	// The bike messages -show-keys finds
	captureStdout(t, func() { ShowKeys(leakEmail, ShowKeysStatic, Options{BikeFilter: "all", CleartextKeys: true}) })
	account, _ = bikeCache.load(leakEmail, false)
	if b := savedBikeOf(account, leakS2Frame); b == nil || len(b.BikeMessages) != 1 || b.BikeMessages[0].Content != leakMessage {
		t.Errorf("bike messages not saved: %+v", b)
	}
}

// With VANMOOF_CACHE_KEY set the cache files are encrypted, and with a wrong one what's
// saved is neither used nor overwritten
func TestCacheEncrypted(t *testing.T) {
	dir := filepath.Dir(useTempCache(t, "secret"))
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	fakeVanMoof(t)

	key := printedPrivateKey(getCert(t, Options{BikeFilter: "all"}))
	for name, data := range cacheFiles(t, dir) {
		if !hasCacheHeader([]byte(data)) || strings.Contains(data, key) || strings.Contains(data, leakName) || strings.Contains(data, leakBLEKey) {
			t.Errorf("%s isn't encrypted", name)
		}
	}
	if account, _ := bikeCache.load(leakEmail, false); account.Key == nil || account.Key.PrivateKey != key {
		t.Errorf("key pair not saved: %+v", account.Key)
	}

	before := cacheFiles(t, dir)
	t.Setenv("VANMOOF_CACHE_KEY", "wrong")
	captureStdout(t, func() {
		if account := loadAccount(leakEmail, Options{}); account.Key != nil {
			t.Error("saved key pair used with the wrong VANMOOF_CACHE_KEY")
		}
		saveAccount(leakEmail, savedAccount{Key: &savedKeyPair{PrivateKey: "other", PublicKey: "other"}}, Options{})
	})
	if after := cacheFiles(t, dir); !maps.Equal(before, after) {
		t.Error("cache overwritten with the wrong VANMOOF_CACHE_KEY")
	}
}

// With -no-cache nothing is read or saved: a run has a new key pair, and leaves the cache
// as it was
func TestNoCacheSavesNothing(t *testing.T) {
	dir := filepath.Dir(useTempCache(t, ""))
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	fakeVanMoof(t)

	first := printedPrivateKey(getCert(t, Options{BikeFilter: "all", NoCache: true}))
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cache folder created with -no-cache: %v", err)
	}

	saved := printedPrivateKey(getCert(t, Options{BikeFilter: "all", CleartextKeys: true}))
	before := cacheFiles(t, dir)
	key := printedPrivateKey(getCert(t, Options{BikeFilter: "all", NoCache: true}))
	if key == "" || key == saved || key == first {
		t.Errorf("-no-cache run used the private key %q (saved %q, first %q)", key, saved, first)
	}
	if after := cacheFiles(t, dir); !maps.Equal(before, after) {
		t.Error("cache changed by a run with -no-cache")
	}
}

// cacheFiles returns the contents of the files in the cache folder dir, by name
func cacheFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]string)
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[e.Name()] = string(data)
	}
	return files
}

// -show-saved shows what's saved, keys included, and with -redact none of it
func TestShowSaved(t *testing.T) {
	useTempCache(t, "")
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	certs, pubKeys := fakeVanMoof(t)
	captureStdout(t, func() {
		GetCert(leakEmail, Options{BikeFilter: "all", CleartextKeys: true})
		ShowKeys(leakEmail, ShowKeysStatic, Options{BikeFilter: "all", CleartextKeys: true})
	})
	account, _ := bikeCache.load(leakEmail, false)

	var err error
	out := captureStdout(t, func() { err = ShowSaved(leakEmail, false) })
	if err != nil {
		t.Fatal(err)
	}
	want := []string{account.Key.PrivateKey, leakBLEKey, leakMessage, leakName, leakSA5Frame}
	for _, b := range account.Bikes {
		if b.Certificate != "" {
			want = append(want, b.Certificate)
		}
	}
	for _, s := range want {
		if !strings.Contains(out, s) {
			t.Errorf("-show-saved lacks %q", s)
		}
	}

	setRedaction(t, true, false)
	out = captureStdout(t, func() { err = ShowSaved(leakEmail, true) })
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	hidden := append(append([]string{home, account.Key.PrivateKey}, leakSecrets...), leakPersonal...)
	for _, s := range append(append(hidden, *certs...), *pubKeys...) {
		if strings.Contains(out, s) {
			t.Errorf("-show-saved -redact shows %q", s)
		}
	}
	for _, s := range []string{`"frame_number": "LLLLLLDDDDDLL"`, `"model": "SA5"`} {
		if !strings.Contains(out, s) {
			t.Errorf("-show-saved -redact lacks %s", s)
		}
	}

	setRedaction(t, false, false)
	if out := captureStdout(t, func() { ShowSaved("nobody@example.com", false) }); !strings.Contains(out, "Nothing saved") {
		t.Errorf("for an account without saved data: %q", out)
	}
}

// Without VANMOOF_CACHE_KEY, the key pair, certificates, BLE keys and customer data are only
// saved, unencrypted, with -cleartext-keys. What's saved is used either way.
func TestCleartextKeysNeedConsent(t *testing.T) {
	dir := filepath.Dir(useTempCache(t, ""))
	t.Setenv("VANMOOF_PASSWORD", leakPassword)
	fakeVanMoof(t)

	out := getCert(t, Options{BikeFilter: "all"})
	if !strings.Contains(out, "add -cleartext-keys") {
		t.Errorf("no note on what isn't saved:\n%s", out)
	}
	if files := slices.Sorted(maps.Keys(cacheFiles(t, dir))); !slices.Equal(files, []string{"tokens.json"}) {
		t.Errorf("saved without -cleartext-keys: %v", files)
	}
	if again := printedPrivateKey(getCert(t, Options{BikeFilter: "all"})); again == printedPrivateKey(out) {
		t.Error("key pair kept without -cleartext-keys")
	}

	key := printedPrivateKey(getCert(t, Options{BikeFilter: "all", CleartextKeys: true}))
	if files := slices.Sorted(maps.Keys(cacheFiles(t, dir))); !slices.Equal(files, []string{"bikes.json", "customer_data.json", "tokens.json"}) {
		t.Errorf("saved with -cleartext-keys: %v", files)
	}

	// Without it again, the saved key pair is used, but nothing new is saved
	before := cacheFiles(t, dir)
	if out := getCert(t, Options{BikeFilter: "all"}); printedPrivateKey(out) != key {
		t.Errorf("saved key pair not used:\n%s", out)
	}
	after := cacheFiles(t, dir)
	for _, name := range []string{"bikes.json", "customer_data.json"} {
		if before[name] != after[name] {
			t.Errorf("%s changed without -cleartext-keys", name)
		}
	}
}

// -show-saved reports a cache it can't read, instead of showing nothing
func TestShowSavedUnreadable(t *testing.T) {
	useTempCache(t, "secret")
	captureStdout(t, func() {
		bikeCache.save(leakEmail, savedAccount{Key: &savedKeyPair{PrivateKey: "private", PublicKey: "public"}}, false)
	})
	t.Setenv("VANMOOF_CACHE_KEY", "wrong")
	if err := ShowSaved(leakEmail, false); err == nil || !strings.Contains(err.Error(), "can't decrypt") {
		t.Errorf("err = %v", err)
	}

	// The customer data too
	path, _ := customerDataCache.path()
	if err := os.WriteFile(path, []byte("not JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VANMOOF_CACHE_KEY", "secret")
	if err := ShowSaved(leakEmail, false); err == nil || !strings.Contains(err.Error(), "customer_data.json") {
		t.Errorf("err = %v for unreadable customer data", err)
	}
}

// With -redact, -show-saved shows what escaping a control character made invalid JSON,
// and so can't be indented, on one line: redacted all the same
func TestShowSavedOneLine(t *testing.T) {
	useTempCache(t, "")
	data := json.RawMessage("{\"model\":\"S\x7f3\",\"name\":\"" + leakName + "\"}")
	captureStdout(t, func() { customerDataCache.save(leakEmail, data, false) })
	setRedaction(t, true, false)
	out := captureStdout(t, func() {
		if err := ShowSaved(leakEmail, false); err != nil {
			t.Error(err)
		}
	})
	if want := `{"customer_data":{"model":"S\x7f3","name":"[REDACTED]"}}` + "\n"; out != want {
		t.Errorf("output %q, want %q", out, want)
	}
}

// Bike messages are saved for a bike with a frame number, as the saved bikes go by it
func TestBikeMessagesNeedFrameNumber(t *testing.T) {
	var account savedAccount
	account.setBikeMessages(BikeDetail{BikeID: leakS2ID}, []BikeMessage{{Content: leakMessage}})
	if len(account.Bikes) != 0 {
		t.Errorf("saved %+v", account.Bikes)
	}
}
