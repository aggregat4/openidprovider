package crypto

import (
	"crypto/rsa"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func ReadRSAPrivateKey(filename string) (*rsa.PrivateKey, error) {
	privateKeyFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return privateKey, err
}

func ReadRSAPublicKey(filename string) (*rsa.PublicKey, error) {
	publicKeyFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyFile)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}
