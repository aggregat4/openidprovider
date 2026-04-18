package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

const (
	opaqueTokenEntropyBytes = 32
	tokenHintPrefixLength   = 12
)

func GenerateOpaqueToken() (string, error) {
	raw := make([]byte, opaqueTokenEntropyBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func HashOpaqueToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TokenHintPrefix(token string) string {
	if len(token) <= tokenHintPrefixLength {
		return token
	}
	return token[:tokenHintPrefixLength]
}
