package oidc

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var stateSecret = []byte("test-state-secret")

func testState() State {
	return State{
		Provider:     "google",
		Nonce:        "nonce-123",
		CodeVerifier: "verifier-456",
		RedirectURI:  "https://app.example.com/auth/sso/google/callback",
	}
}

func TestState_Roundtrip(t *testing.T) {
	token, err := SignState(stateSecret, testState())
	if err != nil {
		t.Fatalf("signing state: %v", err)
	}

	got, err := ParseState(stateSecret, token)
	if err != nil {
		t.Fatalf("parsing state: %v", err)
	}
	if got.Provider != "google" || got.Nonce != "nonce-123" ||
		got.CodeVerifier != "verifier-456" ||
		got.RedirectURI != "https://app.example.com/auth/sso/google/callback" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
}

func TestState_Expired(t *testing.T) {
	s := testState()
	s.Use = stateUse
	now := time.Now()
	s.IssuedAt = jwt.NewNumericDate(now.Add(-20 * time.Minute))
	s.ExpiresAt = jwt.NewNumericDate(now.Add(-10 * time.Minute))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, s).SignedString(stateSecret)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if _, err := ParseState(stateSecret, token); err == nil {
		t.Fatal("expected error for expired state")
	}
}

func TestState_Tampered(t *testing.T) {
	token, err := SignState(stateSecret, testState())
	if err != nil {
		t.Fatalf("signing state: %v", err)
	}

	// Flip a character in the signature part.
	parts := strings.Split(token, ".")
	sig := []byte(parts[2])
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)

	if _, err := ParseState(stateSecret, tampered); err == nil {
		t.Fatal("expected error for tampered state")
	}
}

func TestState_WrongSecret(t *testing.T) {
	token, err := SignState(stateSecret, testState())
	if err != nil {
		t.Fatalf("signing state: %v", err)
	}
	if _, err := ParseState([]byte("another-secret"), token); err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

// A session JWT (same secret, same alg) must never be accepted as SSO state.
func TestState_RejectsSessionToken(t *testing.T) {
	claims := jwt.MapClaims{
		"user_id": "11111111-2222-3333-4444-555555555555",
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(stateSecret)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if _, err := ParseState(stateSecret, token); err == nil {
		t.Fatal("expected session-style token to be rejected as state")
	}
}

func TestState_MissingFields(t *testing.T) {
	s := testState()
	s.CodeVerifier = ""
	token, err := SignState(stateSecret, s)
	if err != nil {
		t.Fatalf("signing state: %v", err)
	}
	if _, err := ParseState(stateSecret, token); err == nil {
		t.Fatal("expected error for state with missing fields")
	}
}

func TestCodeChallengeS256(t *testing.T) {
	// RFC 7636 appendix B reference vector.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := CodeChallengeS256(verifier); got != want {
		t.Errorf("challenge mismatch: got %s want %s", got, want)
	}
}

func TestNewNonceAndVerifier_Random(t *testing.T) {
	n1, err := NewNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	n2, _ := NewNonce()
	if n1 == n2 {
		t.Error("nonces should be random")
	}
	v, err := NewCodeVerifier()
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	// RFC 7636 requires 43..128 chars; 32 bytes base64url = 43 chars.
	if len(v) < 43 || len(v) > 128 {
		t.Errorf("code_verifier length %d out of RFC 7636 range", len(v))
	}
}
