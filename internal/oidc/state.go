package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// stateUse tags state tokens so that other HS256 JWTs signed with the same
// app secret (e.g. session tokens) can never be replayed as OAuth state.
const stateUse = "sso_state"

// StateTTL bounds how long a login round-trip through the IdP may take.
const StateTTL = 10 * time.Minute

// State carries the OAuth round-trip context. It is signed (HS256, app JWT
// secret) and travels in the IdP's `state` parameter, so the flow needs no
// server-side session storage and works across multiple instances.
type State struct {
	Provider     string `json:"provider"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
	// ExtRedirect, when set, is where the callback sends the session token
	// instead of the SPA handoff page: the browser extension's
	// https://<id>.chromiumapp.org/ URL (validated by the SSO handler
	// before signing). Empty for normal web logins.
	ExtRedirect string `json:"ext_redirect,omitempty"`
	Use         string `json:"use"`
	jwt.RegisteredClaims
}

// SignState packs the state into a compact JWT valid for StateTTL.
func SignState(secret []byte, s State) (string, error) {
	s.Use = stateUse
	now := time.Now()
	s.IssuedAt = jwt.NewNumericDate(now)
	s.ExpiresAt = jwt.NewNumericDate(now.Add(StateTTL))
	return jwt.NewWithClaims(jwt.SigningMethodHS256, s).SignedString(secret)
}

// ParseState verifies (signature, expiry, purpose) and unpacks a state JWT.
func ParseState(secret []byte, token string) (*State, error) {
	var s State
	_, err := jwt.ParseWithClaims(token, &s, func(t *jwt.Token) (any, error) {
		return secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	if err != nil {
		return nil, fmt.Errorf("invalid state: %w", err)
	}
	if s.Use != stateUse {
		return nil, fmt.Errorf("invalid state: wrong token purpose")
	}
	if s.Provider == "" || s.Nonce == "" || s.CodeVerifier == "" || s.RedirectURI == "" {
		return nil, fmt.Errorf("invalid state: missing fields")
	}
	return &s, nil
}

// randomToken returns a URL-safe random string with n bytes of entropy.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewNonce returns a random nonce binding the ID token to this attempt.
func NewNonce() (string, error) { return randomToken(16) }

// NewCodeVerifier returns a PKCE code_verifier (RFC 7636 §4.1).
func NewCodeVerifier() (string, error) { return randomToken(32) }

// CodeChallengeS256 derives the S256 code_challenge for a verifier.
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
