package vanmoof

import (
	"bytes"
	"os"
	"testing"
)

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
