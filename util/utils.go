package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

var pkceMask = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_~."

func GetRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// getRandomBytes generates random bytes of the specified length
func getRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// generateCodeVerifier generates a code verifier of the specified length using PKCE mask
func generateCodeVerifier(length int) (string, error) {
	pkceMask := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_.~"
	randomBytes, err := getRandomBytes(length)
	if err != nil {
		return "", err
	}
	verifier := make([]byte, length)
	for i, b := range randomBytes {
		verifier[i] = pkceMask[int(b)%len(pkceMask)]
	}
	return string(verifier), nil
}

func GenerateCodeVerifier(length int) (string, error) {
	bytes, err := GetRandomBytes(length)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, b := range bytes {
		sb.WriteByte(pkceMask[int(b)%len(pkceMask)])
	}
	return sb.String(), nil
}

func GenerateCodeChallengeAndVerifier(length int, method string) (string, string, error) {
	verifier, err := generateCodeVerifier(length)
	if err != nil {
		return "", "", err
	}
	switch method {
	case "plain":
		return verifier, verifier, nil
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		challenge := toUrlEncodedBase64(h[:])
		return verifier, challenge, nil
	default:
		return "", "", fmt.Errorf("bad challenge method")
	}
}

func Sha256Hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func toBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func toUrlEncodedBase64(data []byte) string {
	base64Str := toBase64(data)
	encoded := strings.ReplaceAll(base64Str, "=", "")
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	return encoded
}

func GetSortedScope(scope string) string {
	scopes := strings.Fields(scope)
	sort.Strings(scopes)
	return strings.Join(scopes, " ")
}

func RecordCacheKey(record map[string]string) string {
	keys := make([]string, 0, len(record))
	for k, v := range record {
		if v != "" {
			keys = append(keys, k+"="+v)
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, "&")
}

func EncodeState(state interface{}) string {
	randomBytes, _ := GetRandomBytes(32)
	randomBase64 := toUrlEncodedBase64(randomBytes)
	var encodedState string
	if state != nil {
		stateJSON, err := json.Marshal(state)
		if err != nil {
			panic(err) // Handle the error appropriately in your application
		}
		escapedState := url.QueryEscape(string(stateJSON))
		encodedState = toUrlEncodedBase64([]byte(escapedState))
	}
	return randomBase64 + "." + encodedState
}

func GenerateNonce() (string, error) {
	// Generate 32 random bytes
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Convert bytes to base64 string
	nonce := base64.StdEncoding.EncodeToString(randomBytes)
	return nonce, nil
}