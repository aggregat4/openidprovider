package server

import (
	"aggregat4/openidprovider/internal/domain"
	"encoding/json"

	"github.com/altcha-org/altcha-lib-go"
)

// CaptchaVerifier defines the interface for captcha verification
type CaptchaVerifier interface {
	CreateChallenge() (string, error)
	VerifySolution(solution string) (bool, error)
}

// AltchaVerifier implements CaptchaVerifier using the ALTCHA library
type AltchaVerifier struct {
	config domain.AltchaConfiguration
}

// NewAltchaVerifier creates a new ALTCHA-based captcha verifier
func NewAltchaVerifier(config domain.AltchaConfiguration) CaptchaVerifier {
	return &AltchaVerifier{config: config}
}

// CreateChallenge creates a new ALTCHA challenge
func (a *AltchaVerifier) CreateChallenge() (string, error) {
	challenge, err := altcha.CreateChallenge(altcha.ChallengeOptions{
		HMACKey:    a.config.HMACKey,
		MaxNumber:  a.config.MaxNumber,
		SaltLength: a.config.SaltLength,
	})
	if err != nil {
		return "", err
	}

	challengeJSON, err := json.Marshal(challenge)
	if err != nil {
		return "", err
	}

	return string(challengeJSON), nil
}

// VerifySolution verifies an ALTCHA solution
func (a *AltchaVerifier) VerifySolution(solution string) (bool, error) {
	return altcha.VerifySolution(solution, a.config.HMACKey, true)
}
