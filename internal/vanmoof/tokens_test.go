package vanmoof

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
	salt, nonce := make([]byte, saltSize), make([]byte, nonceSize)
	rand.Read(salt)
	rand.Read(nonce)
	gcm, err := newCacheCipher(passphrase, salt, legacyPBKDF2Iterations)
	if err != nil {
		t.Fatal(err)
	}
	return gcm.Seal(append(append([]byte{}, salt...), nonce...), nonce, plaintext, nil)
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

	if _, err := loadAllTokenCaches(false); err == nil {
		t.Error("truncated cache file loaded without an error")
	}
	saveTokenCache("a@example.com", "authA2", "refreshA2", "appA2", false)
	if after, _ := os.ReadFile(path); !bytes.Equal(truncated, after) {
		t.Error("corrupt cache file was overwritten")
	}
}
