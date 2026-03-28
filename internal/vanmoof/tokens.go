package vanmoof

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/pbkdf2"
)

const tokenCacheDir = ".vanmoof-certificates"
const tokenCacheFile = "tokens.json"
const pbkdf2Iterations = 100_000
const saltSize = 16
const nonceSize = 12

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

// encrypt encrypts plaintext with AES-256-GCM using a key derived from passphrase
// Format: [16 bytes salt][12 bytes nonce][ciphertext + GCM tag]
func encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// salt + nonce + ciphertext
	result := make([]byte, 0, saltSize+nonceSize+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	return result, nil
}

// decrypt decrypts data produced by encrypt
func decrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) < saltSize+nonceSize+aes.BlockSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	salt := data[:saltSize]
	nonce := data[saltSize : saltSize+nonceSize]
	ciphertext := data[saltSize+nonceSize:]

	key := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// loadAllTokenCaches loads the full cache map from disk
func loadAllTokenCaches(debug bool) map[string]CachedTokens {
	path, err := tokenCachePath()
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] Token cache path error: %v\n", err)
		}
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] No token cache found: %v\n", err)
		}
		return nil
	}

	// Decrypt if cache key is set
	if key := getCacheKey(); key != "" {
		plaintext, err := decrypt(data, key)
		if err != nil {
			if debug {
				fmt.Printf("[DEBUG] Token cache decryption failed: %v\n", err)
			}
			return nil
		}
		data = plaintext
		if debug {
			fmt.Println("[DEBUG] Token cache decrypted")
		}
	}

	var cacheMap map[string]CachedTokens
	if err := json.Unmarshal(data, &cacheMap); err != nil {
		if debug {
			fmt.Printf("[DEBUG] Token cache parse error: %v\n", err)
		}
		return nil
	}

	return cacheMap
}

// saveAllTokenCaches writes the full cache map to disk
func saveAllTokenCaches(cacheMap map[string]CachedTokens, debug bool) {
	path, err := tokenCachePath()
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] Token cache path error: %v\n", err)
		}
		return
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		if debug {
			fmt.Printf("[DEBUG] Failed to create token cache dir: %v\n", err)
		}
		return
	}

	data, err := json.MarshalIndent(cacheMap, "", "  ")
	if err != nil {
		if debug {
			fmt.Printf("[DEBUG] Token cache marshal error: %v\n", err)
		}
		return
	}

	// Encrypt if cache key is set
	if key := getCacheKey(); key != "" {
		encrypted, err := encrypt(data, key)
		if err != nil {
			if debug {
				fmt.Printf("[DEBUG] Token cache encryption failed: %v\n", err)
			}
			return
		}
		data = encrypted
		if debug {
			fmt.Println("[DEBUG] Token cache encrypted")
		}
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		if debug {
			fmt.Printf("[DEBUG] Failed to write token cache: %v\n", err)
		}
		return
	}

	if debug {
		fmt.Println("[DEBUG] Token cache saved to disk")
	}
}

// loadTokenCache loads cached tokens from disk for the given email
func loadTokenCache(email string, debug bool) *CachedTokens {
	cacheMap := loadAllTokenCaches(debug)
	if cacheMap == nil {
		return nil
	}

	cached, ok := cacheMap[email]
	if !ok {
		if debug {
			fmt.Printf("[DEBUG] No cached tokens for %s\n", email)
		}
		return nil
	}

	if debug {
		fmt.Printf("[DEBUG] Loaded token cache for %s\n", email)
	}
	return &cached
}

// saveTokenCache saves tokens to disk for the given email, preserving other accounts
func saveTokenCache(email, authToken, refreshToken, appToken string, debug bool) {
	// Load existing cache to preserve other accounts
	cacheMap := loadAllTokenCaches(debug)
	if cacheMap == nil {
		cacheMap = make(map[string]CachedTokens)
	}

	cacheMap[email] = CachedTokens{
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
