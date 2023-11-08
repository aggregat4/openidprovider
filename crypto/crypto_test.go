package crypto

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "password123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Errorf("HashPassword returned an error: %v", err)
	}

	if len(hash) == 0 {
		t.Errorf("HashPassword returned an empty hash")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "password123"
	hash, _ := HashPassword(password)

	if !CheckPasswordHash(password, hash) {
		t.Errorf("CheckPasswordHash returned false for a valid password and hash")
	}

	if CheckPasswordHash("wrongpassword", hash) {
		t.Errorf("CheckPasswordHash returned true for an invalid password and valid hash")
	}
}
