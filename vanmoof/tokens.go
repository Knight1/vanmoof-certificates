package vanmoof

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/pbkdf2"
)

const tokenCacheDir = ".vanmoof-certificates"
const tokenCacheFile = "tokens.json"
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

// tokenCachePath returns the full path to the token cache file
func tokenCachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, tokenCacheDir, tokenCacheFile), nil
}

// getCacheKey returns the encryption key from VANMOOF_CACHE_KEY env var, or empty if unset
func getCacheKey() string {
	return os.Getenv("VANMOOF_CACHE_KEY")
}

// newCacheCipher returns AES-256-GCM with a key derived from passphrase
func newCacheCipher(passphrase string, salt []byte, iterations int) (cipher.AEAD, error) {
	key := pbkdf2.Key([]byte(passphrase), salt, iterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// encrypt encrypts plaintext with AES-256-GCM using a key derived from passphrase
// Format: [header][16 bytes salt][12 bytes nonce][ciphertext + GCM tag]
func encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	header := binary.BigEndian.AppendUint32([]byte(cacheMagic), pbkdf2Iterations)

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	gcm, err := newCacheCipher(passphrase, salt, pbkdf2Iterations)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// header + salt + nonce + ciphertext
	result := make([]byte, 0, cacheHeaderSize+saltSize+nonceSize+len(plaintext)+gcm.Overhead())
	result = append(result, header...)
	result = append(result, salt...)
	result = append(result, nonce...)
	return gcm.Seal(result, nonce, plaintext, header), nil
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

	salt := data[:saltSize]
	nonce := data[saltSize : saltSize+nonceSize]
	ciphertext := data[saltSize+nonceSize:]

	gcm, err := newCacheCipher(passphrase, salt, iterations)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, header)
}

// loadAllTokenCaches loads the full cache map from disk. With no cache file yet it
// returns a nil map and no error. A cache file that exists but can't be read, decrypted
// or parsed is an error instead, so callers don't overwrite it: it may hold other
// accounts' tokens, or be encrypted with a different VANMOOF_CACHE_KEY.
func loadAllTokenCaches(debug bool) (map[string]Tokens, error) {
	path, err := tokenCachePath()
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] Token cache path error: %v\n", ScrubText(err.Error()))
		}
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if debug {
			fmt.Printf("[DEBUG] No token cache found: %v\n", ScrubText(err.Error()))
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	key := getCacheKey()

	// An unencrypted (plain JSON) cache is used as is. If VANMOOF_CACHE_KEY has been
	// set since it was written, it's encrypted right away, keeping every account.
	var plainMap map[string]Tokens
	if err := json.Unmarshal(data, &plainMap); err == nil {
		if key != "" && plainMap != nil {
			if debug {
				fmt.Println("[DEBUG] Encrypting the unencrypted token cache with VANMOOF_CACHE_KEY")
			}
			saveAllTokenCaches(plainMap, debug)
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
		fmt.Println("[DEBUG] Token cache decrypted")
	}

	var cacheMap map[string]Tokens
	if err := json.Unmarshal(plaintext, &cacheMap); err != nil {
		return nil, fmt.Errorf("%s is corrupt (delete it to start over): %w", path, err)
	}

	// Encrypted by an earlier version, with the weaker key derivation: upgrade it now
	if !hasCacheHeader(data) {
		if debug {
			fmt.Println("[DEBUG] Re-encrypting the token cache with the current key derivation")
		}
		saveAllTokenCaches(cacheMap, debug)
	}

	return cacheMap, nil
}

// saveAllTokenCaches writes the full cache map to disk
func saveAllTokenCaches(cacheMap map[string]Tokens, debug bool) {
	path, err := tokenCachePath()
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] Token cache path error: %v\n", ScrubText(err.Error()))
		}
		return
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		if debug {
			fmt.Printf("[DEBUG] Failed to create token cache dir: %v\n", ScrubText(err.Error()))
		}
		return
	}

	data, err := json.MarshalIndent(cacheMap, "", "  ")
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] Token cache marshal error: %v\n", ScrubText(err.Error()))
		}
		return
	}

	// Encrypt if cache key is set
	key := getCacheKey()
	if key != "" {
		encrypted, err := encrypt(data, key)
		if err != nil {
			if debug {
				fmt.Printf("[DEBUG] Token cache encryption failed: %v\n", ScrubText(err.Error()))
			}
			return
		}
		data = encrypted
		if debug {
			fmt.Println("[DEBUG] Token cache encrypted")
		}
	}

	_, statErr := os.Stat(path)
	if err := writeFileAtomic(path, data); err != nil {
		if debug {
			fmt.Printf("[DEBUG] Failed to write token cache: %v\n", ScrubText(err.Error()))
		}
		return
	}

	if debug {
		fmt.Println("[DEBUG] Token cache saved to disk")
	}
	// Said once, when the cache is created, rather than on every run
	if key == "" && errors.Is(statErr, os.ErrNotExist) {
		fmt.Printf("Note: tokens are cached unencrypted in %s: set VANMOOF_CACHE_KEY to encrypt them, or use -no-cache\n", ScrubText(path))
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

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// loadTokenCache loads cached tokens from disk for the given email
func loadTokenCache(email string, debug bool) *Tokens {
	cacheMap, err := loadAllTokenCaches(debug)
	if err != nil {
		fmt.Printf("WARNING: Token cache not used: %v\n", ScrubText(err.Error()))
		return nil
	}
	if cacheMap == nil {
		return nil
	}

	cached, ok := cacheMap[email]
	if !ok {
		if debug {
			fmt.Printf("[DEBUG] No cached tokens for %s\n", Redact(email))
		}
		return nil
	}

	if debug {
		fmt.Printf("[DEBUG] Loaded token cache for %s\n", Redact(email))
	}
	return &cached
}

// saveTokenCache saves tokens to disk for the given email, preserving other accounts.
// A cache file that can't be read is left alone rather than overwritten.
func saveTokenCache(email, authToken, refreshToken, appToken string, debug bool) {
	// Load existing cache to preserve other accounts
	cacheMap, err := loadAllTokenCaches(debug)
	if err != nil {
		fmt.Println("WARNING: New tokens not cached, so the token cache isn't overwritten")
		return
	}
	if cacheMap == nil {
		cacheMap = make(map[string]Tokens)
	}

	cacheMap[email] = Tokens{
		AuthToken:    authToken,
		AppToken:     appToken,
		RefreshToken: refreshToken,
	}

	saveAllTokenCaches(cacheMap, debug)
}

// isJWTExpired checks if a JWT token is expired (with 60s buffer)
func isJWTExpired(tokenString string) bool {
	if tokenString == "" {
		return true
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return true
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return true
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return true
	}

	// Expired if within 60 seconds of expiry
	return time.Now().Unix() >= int64(exp)-60
}
