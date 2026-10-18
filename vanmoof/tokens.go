package vanmoof

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// cacheDir is the cache's folder in the home directory
const cacheDir = ".vanmoof-certificates"
const saltSize = 16
const nonceSize = 12

// An encrypted cache starts with cacheMagic and the PBKDF2 iteration count (4 bytes, big
// endian), which GCM authenticates along with the ciphertext. Caches written before this
// header existed have none and used 100,000 iterations; they're re-encrypted when read.
const (
	cacheMagic             = "VMC2"
	cacheHeaderSize        = len(cacheMagic) + 4
	pbkdf2Iterations       = 600_000 // OWASP's recommendation for PBKDF2-HMAC-SHA256
	legacyPBKDF2Iterations = 100_000
	maxPBKDF2Iterations    = 10_000_000
)

// cacheFile is one of the cache's files: a JSON object with an entry of type T for each
// account (email address), encrypted with VANMOOF_CACHE_KEY if it's set
type cacheFile[T any] struct {
	name string // the file's name in cacheDir
	what string // what it holds, for messages
}

var tokenCache = cacheFile[Tokens]{name: "tokens.json", what: "tokens"}

// tokenCachePath returns the full path to the token cache file
func tokenCachePath() (string, error) {
	return tokenCache.path()
}

// path returns the file's full path
func (c cacheFile[T]) path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, cacheDir, c.name), nil
}

// getCacheKey returns the encryption key from VANMOOF_CACHE_KEY env var, or empty if unset
func getCacheKey() string {
	return os.Getenv("VANMOOF_CACHE_KEY")
}

// newCacheCipher returns AES-256-GCM with a key derived from passphrase. It handles the
// nonce itself: Seal puts a random one before the ciphertext, where Open reads it from.
// With a 16 byte salt and a 32 byte key, none of the steps fails.
func newCacheCipher(passphrase string, salt []byte, iterations int) cipher.AEAD {
	key := must(pbkdf2.Key(sha256.New, passphrase, salt, iterations, 32))
	return must(cipher.NewGCMWithRandomNonce(must(aes.NewCipher(key))))
}

// encrypt encrypts plaintext with AES-256-GCM using a key derived from passphrase
// Format: [header][16 bytes salt][12 bytes nonce][ciphertext + GCM tag]
func encrypt(plaintext []byte, passphrase string) []byte {
	header := binary.BigEndian.AppendUint32([]byte(cacheMagic), pbkdf2Iterations)

	salt := make([]byte, saltSize)
	rand.Read(salt) // never fails

	gcm := newCacheCipher(passphrase, salt, pbkdf2Iterations)

	// header + salt, then Seal adds the nonce and ciphertext
	return gcm.Seal(slices.Concat(header, salt), nil, plaintext, header)
}

// hasCacheHeader reports whether encrypted cache data is in the current format
func hasCacheHeader(data []byte) bool {
	return len(data) >= cacheHeaderSize && string(data[:len(cacheMagic)]) == cacheMagic
}

// decrypt decrypts data produced by encrypt, or by its earlier version without header
func decrypt(data []byte, passphrase string) ([]byte, error) {
	iterations, header := legacyPBKDF2Iterations, []byte(nil)
	if hasCacheHeader(data) {
		header, data = data[:cacheHeaderSize], data[cacheHeaderSize:]
		n := binary.BigEndian.Uint32(header[len(cacheMagic):])
		if n == 0 || n > maxPBKDF2Iterations {
			return nil, fmt.Errorf("unsupported key derivation iteration count %d", n)
		}
		iterations = int(n)
	}

	if len(data) < saltSize+nonceSize+aes.BlockSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// nonce + ciphertext
	return newCacheCipher(passphrase, data[:saltSize], iterations).Open(nil, nil, data[saltSize:], header)
}

// loadAll loads all accounts' entries from disk. With no file yet it returns a nil map and
// no error. A file that exists but can't be read, decrypted or parsed is an error instead,
// so callers don't overwrite it: it may hold other accounts' entries, or be encrypted with
// a different VANMOOF_CACHE_KEY.
func (c cacheFile[T]) loadAll(debug bool) (map[string]T, error) {
	path, err := c.path()
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] Cache path error: %v\n", ScrubText(err.Error()))
		}
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if debug {
			fmt.Printf("[DEBUG] No %s cached yet: %v\n", c.what, ScrubText(err.Error()))
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	key := getCacheKey()

	// An unencrypted (plain JSON) file is used as is. If VANMOOF_CACHE_KEY has been set
	// since it was written, it's encrypted right away, keeping every account.
	var plainMap map[string]T
	if err := json.Unmarshal(data, &plainMap); err == nil {
		if key != "" && plainMap != nil {
			if debug {
				fmt.Printf("[DEBUG] Encrypting the unencrypted %s with VANMOOF_CACHE_KEY\n", c.name)
			}
			c.saveAll(plainMap, debug)
		}
		return plainMap, nil
	}

	// Anything else has to be encrypted
	if key == "" {
		return nil, fmt.Errorf("%s is encrypted or corrupt: set VANMOOF_CACHE_KEY if you use one, or delete the file to start over", path)
	}
	plaintext, err := decrypt(data, key)
	if err != nil {
		return nil, fmt.Errorf("can't decrypt %s: wrong VANMOOF_CACHE_KEY, or the file is corrupt (delete it to start over)", path)
	}
	if debug {
		fmt.Printf("[DEBUG] %s decrypted\n", c.name)
	}

	var entries map[string]T
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return nil, fmt.Errorf("%s is corrupt (delete it to start over): %w", path, err)
	}

	// Encrypted by an earlier version, with the weaker key derivation: upgrade it now
	if !hasCacheHeader(data) {
		if debug {
			fmt.Printf("[DEBUG] Re-encrypting %s with the current key derivation\n", c.name)
		}
		c.saveAll(entries, debug)
	}

	return entries, nil
}

// saveAll writes all accounts' entries to disk
func (c cacheFile[T]) saveAll(entries map[string]T, debug bool) {
	path, err := c.path()
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] Cache path error: %v\n", ScrubText(err.Error()))
		}
		return
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		if debug {
			fmt.Printf("[DEBUG] Failed to create the cache folder: %v\n", ScrubText(err.Error()))
		}
		return
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] %s marshal error: %v\n", c.name, ScrubText(err.Error()))
		}
		return
	}

	// Encrypt if cache key is set
	key := getCacheKey()
	if key != "" {
		data = encrypt(data, key)
		if debug {
			fmt.Printf("[DEBUG] %s encrypted\n", c.name)
		}
	}

	_, statErr := os.Stat(path)
	if err := writeFileAtomic(path, data); err != nil {
		if debug {
			fmt.Printf("[DEBUG] Failed to write %s: %v\n", c.name, ScrubText(err.Error()))
		}
		return
	}

	if debug {
		fmt.Printf("[DEBUG] %s saved\n", c.name)
	}
	// Said once, when the file is created, rather than on every run
	if key == "" && errors.Is(statErr, os.ErrNotExist) {
		fmt.Printf("Note: %s are cached unencrypted in %s: set VANMOOF_CACHE_KEY to encrypt them, or use -no-cache\n", c.what, ScrubText(path))
	}
}

// writeFileAtomic writes data to a new file next to path (mode 0600), then renames it
// over path: path holds either the old or the new data, even if the write fails halfway.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // fails harmlessly once renamed

	// The first error counts, and the file is closed either way
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	return err
}

// load returns the account's entry, and whether there is one. A file it can't use is
// reported, and treated as empty.
func (c cacheFile[T]) load(email string, debug bool) (T, bool) {
	entries, err := c.loadAll(debug)
	if err != nil {
		fmt.Printf("WARNING: Cached %s not used: %v\n", c.what, ScrubText(err.Error()))
	}
	entry, ok := entries[email]
	if debug {
		if ok {
			fmt.Printf("[DEBUG] Loaded the cached %s for %s\n", c.what, Redact(email))
		} else if err == nil {
			fmt.Printf("[DEBUG] No cached %s for %s\n", c.what, Redact(email))
		}
	}
	return entry, ok
}

// save saves the account's entry, keeping the other accounts'. A file that can't be read
// is left alone rather than overwritten.
func (c cacheFile[T]) save(email string, entry T, debug bool) {
	entries, err := c.loadAll(debug)
	if err != nil {
		fmt.Printf("WARNING: New %s not cached, so %s isn't overwritten\n", c.what, c.name)
		return
	}
	if entries == nil {
		entries = make(map[string]T)
	}
	entries[email] = entry
	c.saveAll(entries, debug)
}

// loadTokenCache loads cached tokens from disk for the given email
func loadTokenCache(email string, debug bool) *Tokens {
	tokens, ok := tokenCache.load(email, debug)
	if !ok {
		return nil
	}
	return &tokens
}

// saveTokenCache saves tokens to disk for the given email, preserving other accounts
func saveTokenCache(email, authToken, refreshToken, appToken string, debug bool) {
	tokenCache.save(email, Tokens{AuthToken: authToken, AppToken: appToken, RefreshToken: refreshToken}, debug)
}

// isJWTExpired checks if a JWT token is expired (with 60s buffer)
func isJWTExpired(tokenString string) bool {
	if tokenString == "" {
		return true
	}

	// ParseUnverified decodes the claims into this map
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	if _, _, err := parser.ParseUnverified(tokenString, claims); err != nil {
		return true
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return true
	}

	// Expired if within 60 seconds of expiry
	return time.Now().Unix() >= int64(exp)-60
}
