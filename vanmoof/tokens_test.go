package vanmoof

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTokenCacheEncryptionFormat(t *testing.T) {
	data, err := encrypt([]byte(`{"a":1}`), "secret")
	if err != nil {
		t.Fatal(err)
	}
	if !hasCacheHeader(data) || binary.BigEndian.Uint32(data[len(cacheMagic):cacheHeaderSize]) != pbkdf2Iterations {
		t.Fatalf("no header with %d iterations: %x", pbkdf2Iterations, data[:cacheHeaderSize])
	}
	if plain, err := decrypt(data, "secret"); err != nil || string(plain) != `{"a":1}` {
		t.Errorf("decrypt = %q, %v", plain, err)
	}

	// The header is authenticated, so lowering the iteration count doesn't decrypt
	tampered := append([]byte{}, data...)
	binary.BigEndian.PutUint32(tampered[len(cacheMagic):], pbkdf2Iterations-1)
	if _, err := decrypt(tampered, "secret"); err == nil {
		t.Error("decrypted with a tampered iteration count")
	}
	// and an absurd one is refused before deriving a key with it
	binary.BigEndian.PutUint32(tampered[len(cacheMagic):], maxPBKDF2Iterations+1)
	if _, err := decrypt(tampered, "secret"); err == nil || !strings.Contains(err.Error(), "iteration count") {
		t.Errorf("err = %v, want unsupported iteration count", err)
	}
}

// legacyEncrypt is how caches were encrypted before the header: 100,000 iterations and
// only salt, nonce and ciphertext
func legacyEncrypt(t *testing.T, plaintext []byte, passphrase string) []byte {
	t.Helper()
	salt := make([]byte, saltSize)
	rand.Read(salt)
	gcm, err := newCacheCipher(passphrase, salt, legacyPBKDF2Iterations)
	if err != nil {
		t.Fatal(err)
	}
	return gcm.Seal(salt, nil, plaintext, nil) // salt, nonce, ciphertext
}

// Caches that earlier versions of the tool wrote still decrypt: in the current format, and
// in the one from before its header
func TestTokenCacheEarlierVersionsDecrypt(t *testing.T) {
	const plaintext = `{"a@example.com":{"auth_token":"authA"}}`
	caches := map[string]string{
		"current": "564d4332000927c0c6105658d01dbcc457637dae4df1297f2d6f2b7d698a8044fdc3fe70c3d22ab09132345c6f87515d94aee6f5e2f45ba2e2a684254b14bc832019f0f342d13cb948200d92bf3dbe8c55b8ae9c56c1e878b69dd61a",
		"legacy":  "194bd48e80545179cdf6401a619b4c200e18e3b594d7be01aa4d7f089ad7f81be295312b06d969ec2c64d1f4277533680d529b8f1d4d8e27ad2a30a4b6358c0516cd1b2410da90a48c0ca03f2717ba70efd20898",
	}
	for format, cache := range caches {
		data, _ := hex.DecodeString(cache)
		if got, err := decrypt(data, "secret"); err != nil || string(got) != plaintext {
			t.Errorf("%s format: decrypt = %q, %v", format, got, err)
		}
	}
}

func TestTokenCacheLegacyFormatUpgraded(t *testing.T) {
	path := useTempCache(t, "secret")
	os.MkdirAll(filepath.Dir(path), 0700)
	legacy := legacyEncrypt(t, []byte(`{"a@example.com":{"auth_token":"authA"},"b@example.com":{"auth_token":"authB"}}`), "secret")
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}

	if c := loadTokenCache("a@example.com", false); c == nil || c.AuthToken != "authA" {
		t.Fatalf("cache in the old format not readable: %+v", c)
	}
	if data, _ := os.ReadFile(path); !hasCacheHeader(data) {
		t.Error("cache in the old format not re-encrypted in the current one")
	}
	if c := loadTokenCache("b@example.com", false); c == nil || c.AuthToken != "authB" {
		t.Errorf("other account's tokens lost while re-encrypting: %+v", c)
	}
}

func TestTokenCacheWriteIsAtomic(t *testing.T) {
	path := useTempCache(t, "")
	os.MkdirAll(filepath.Dir(path), 0700)
	// e.g. created by hand, readable by others
	if err := os.WriteFile(path, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	saveTokenCache("a@example.com", "authA", "refreshA", "appA", false)
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Errorf("files left next to the cache: %v", entries)
	}
	if info, err := os.Stat(path); err == nil && runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Errorf("cache file mode %v, want 0600", info.Mode().Perm())
	}
	if c := loadTokenCache("a@example.com", false); c == nil || c.AuthToken != "authA" {
		t.Errorf("tokens not saved: %+v", c)
	}
}

func TestTokenCacheUnencryptedNote(t *testing.T) {
	const note = "Note: tokens are cached unencrypted"
	useTempCache(t, "")
	if out := captureStdout(t, func() { saveTokenCache("a@example.com", "authA", "refreshA", "appA", false) }); !strings.Contains(out, note) {
		t.Errorf("no note when creating an unencrypted cache: %q", out)
	}
	if out := captureStdout(t, func() { saveTokenCache("b@example.com", "authB", "refreshB", "appB", false) }); strings.Contains(out, note) {
		t.Error("note repeated for an existing cache")
	}

	useTempCache(t, "secret")
	if out := captureStdout(t, func() { saveTokenCache("a@example.com", "authA", "refreshA", "appA", false) }); strings.Contains(out, note) {
		t.Error("note for an encrypted cache")
	}
}

// useTempCache points the token cache at a fresh home directory and sets VANMOOF_CACHE_KEY.
func useTempCache(t *testing.T, key string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("VANMOOF_CACHE_KEY", key)
	path, err := tokenCachePath()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTokenCacheEncryptedNotOverwrittenWithoutKey(t *testing.T) {
	path := useTempCache(t, "secret")
	saveTokenCache("a@example.com", "authA", "refreshA", "appA", false)
	saveTokenCache("b@example.com", "authB", "refreshB", "appB", false)
	before, _ := os.ReadFile(path)

	// A run without the key can't use the encrypted cache, and must not replace it
	// with an unencrypted one holding only the account it just logged in.
	t.Setenv("VANMOOF_CACHE_KEY", "")
	if c := loadTokenCache("a@example.com", false); c != nil {
		t.Errorf("loaded tokens from an encrypted cache without the key: %+v", c)
	}
	saveTokenCache("a@example.com", "authA2", "refreshA2", "appA2", false)
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("encrypted cache was overwritten by a run without VANMOOF_CACHE_KEY")
	}

	t.Setenv("VANMOOF_CACHE_KEY", "secret")
	if c := loadTokenCache("b@example.com", false); c == nil || c.AuthToken != "authB" {
		t.Errorf("other account's tokens lost: %+v", c)
	}
}

func TestTokenCacheNotOverwrittenWithWrongKey(t *testing.T) {
	path := useTempCache(t, "secret")
	saveTokenCache("a@example.com", "authA", "refreshA", "appA", false)
	before, _ := os.ReadFile(path)

	t.Setenv("VANMOOF_CACHE_KEY", "secrte")
	saveTokenCache("a@example.com", "authA2", "refreshA2", "appA2", false)
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("cache was overwritten by a run with the wrong VANMOOF_CACHE_KEY")
	}

	t.Setenv("VANMOOF_CACHE_KEY", "secret")
	if c := loadTokenCache("a@example.com", false); c == nil || c.AuthToken != "authA" {
		t.Errorf("cache unreadable with the right key afterwards: %+v", c)
	}
}

func TestTokenCacheEncryptedOnceKeyIsSet(t *testing.T) {
	path := useTempCache(t, "")
	saveTokenCache("a@example.com", "authA", "refreshA", "appA", false)
	saveTokenCache("b@example.com", "authB", "refreshB", "appB", false)

	// Setting the key for an existing unencrypted cache encrypts it, keeping both accounts
	t.Setenv("VANMOOF_CACHE_KEY", "secret")
	if c := loadTokenCache("a@example.com", false); c == nil || c.AuthToken != "authA" {
		t.Fatalf("unencrypted cache not usable after setting the key: %+v", c)
	}
	if data, _ := os.ReadFile(path); bytes.Contains(data, []byte("authB")) {
		t.Error("cache still unencrypted after a run with VANMOOF_CACHE_KEY set")
	}
	if c := loadTokenCache("b@example.com", false); c == nil || c.AuthToken != "authB" {
		t.Errorf("other account's tokens lost while encrypting: %+v", c)
	}
}

func TestTokenCacheCorruptNotOverwritten(t *testing.T) {
	path := useTempCache(t, "")
	saveTokenCache("a@example.com", "authA", "refreshA", "appA", false)
	data, _ := os.ReadFile(path)
	truncated := data[:len(data)/2]
	if err := os.WriteFile(path, truncated, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := tokenCache.loadAll(false); err == nil {
		t.Error("truncated cache file loaded without an error")
	}
	saveTokenCache("a@example.com", "authA2", "refreshA2", "appA2", false)
	if after, _ := os.ReadFile(path); !bytes.Equal(truncated, after) {
		t.Error("corrupt cache file was overwritten")
	}
}

func TestIsJWTExpired(t *testing.T) {
	jwt := func(claims string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".c2lnbmF0dXJl"
	}
	now := time.Now().Unix()
	tests := []struct {
		token   string
		expired bool
	}{
		{"", true},
		{"garbage", true},
		{"a.b.c", true},
		{jwt(`{}`), true}, // without expiry
		{jwt(`{"exp":"tomorrow"}`), true},
		{jwt(fmt.Sprintf(`{"exp":%d}`, now-1)), true},
		{jwt(fmt.Sprintf(`{"exp":%d}`, now+30)), true}, // within the minute before it expires
		{jwt(fmt.Sprintf(`{"exp":%d}`, now+3600)), false},
	}
	for _, tt := range tests {
		if got := isJWTExpired(tt.token); got != tt.expired {
			t.Errorf("isJWTExpired(%q) = %v, want %v", tt.token, got, tt.expired)
		}
	}
}

// A cache that can't be written stays as it was, with nothing left next to it, and a
// cache folder that can't be created is reported
func TestCacheWriteFailure(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("file permissions don't stop writing here")
	}
	path := useTempCache(t, "")
	captureStdout(t, func() { saveTokenCache("a@example.com", "authA", "refreshA", "appA", false) })
	before, _ := os.ReadFile(path)
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	out := captureStdout(t, func() { saveTokenCache("a@example.com", "authB", "refreshB", "appB", true) })
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) || !strings.Contains(out, "Failed to write tokens.json") {
		t.Errorf("cache changed, or the failure not reported:\n%s", out)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("files left in the cache folder: %v", entries)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.Chmod(home, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(home, 0700) })
	if out := captureStdout(t, func() { saveTokenCache("a@example.com", "authA", "refreshA", "appA", true) }); !strings.Contains(out, "Failed to create the cache folder") {
		t.Errorf("failure not reported:\n%s", out)
	}
}

// Any passphrase encrypts the cache, and only the same one decrypts it
func TestCacheEncryptionPassphrases(t *testing.T) {
	plaintext := []byte(`{"a@example.com":{"auth_token":"authA"}}`)
	for _, passphrase := range []string{"x", "pässwörd ✓", strings.Repeat("long", 1000), " leading and trailing ", "\x00\xff"} {
		t.Run(fmt.Sprintf("%.10q", passphrase), func(t *testing.T) {
			t.Parallel() // each derives the key three times, which takes a while
			data, err := encrypt(plaintext, passphrase)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := decrypt(data, passphrase); err != nil || !bytes.Equal(got, plaintext) {
				t.Errorf("decrypt = %q, %v", got, err)
			}
			if _, err := decrypt(data, passphrase+"!"); err == nil {
				t.Error("decrypted with another passphrase")
			}
		})
	}
}
