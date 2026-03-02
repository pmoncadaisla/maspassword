package iap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func makeTestKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	kid := "test-kid-1"
	return key, kid
}

func serveJWKS(t *testing.T, key *ecdsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	x := base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes())

	jwks := jwkSet{
		Keys: []jwkKey{
			{
				Kty: "EC",
				Crv: "P-256",
				X:   x,
				Y:   y,
				Kid: kid,
				Alg: "ES256",
				Use: "sig",
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func makeIAPToken(t *testing.T, key *ecdsa.PrivateKey, kid, audience, email, sub string, exp time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":   "https://cloud.google.com/iap",
		"aud":   audience,
		"email": email,
		"sub":   sub,
		"iat":   time.Now().Unix(),
		"exp":   exp.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return signed
}

func TestValidator_ValidToken(t *testing.T) {
	key, kid := makeTestKey(t)
	srv := serveJWKS(t, key, kid)

	audience := "/projects/123/apps/test-app"
	v := NewValidator(audience, srv.URL)

	tokenStr := makeIAPToken(t, key, kid, audience, "user@example.com", "accounts.google.com:12345", time.Now().Add(time.Hour))

	claims, err := v.Validate(tokenStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("expected email user@example.com, got %s", claims.Email)
	}
	if claims.Subject != "accounts.google.com:12345" {
		t.Errorf("expected subject accounts.google.com:12345, got %s", claims.Subject)
	}
}

func TestValidator_ExpiredToken(t *testing.T) {
	key, kid := makeTestKey(t)
	srv := serveJWKS(t, key, kid)

	audience := "/projects/123/apps/test-app"
	v := NewValidator(audience, srv.URL)

	tokenStr := makeIAPToken(t, key, kid, audience, "user@example.com", "sub1", time.Now().Add(-time.Hour))

	_, err := v.Validate(tokenStr)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestValidator_WrongAudience(t *testing.T) {
	key, kid := makeTestKey(t)
	srv := serveJWKS(t, key, kid)

	v := NewValidator("/projects/123/apps/correct", srv.URL)

	tokenStr := makeIAPToken(t, key, kid, "/projects/123/apps/wrong", "user@example.com", "sub1", time.Now().Add(time.Hour))

	_, err := v.Validate(tokenStr)
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestValidator_WrongIssuer(t *testing.T) {
	key, kid := makeTestKey(t)
	srv := serveJWKS(t, key, kid)

	audience := "/projects/123/apps/test-app"
	v := NewValidator(audience, srv.URL)

	// Create token with wrong issuer
	claims := jwt.MapClaims{
		"iss":   "https://evil.com",
		"aud":   audience,
		"email": "user@example.com",
		"sub":   "sub1",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	signed, _ := token.SignedString(key)

	_, err := v.Validate(signed)
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestValidator_UnknownKid(t *testing.T) {
	key, kid := makeTestKey(t)
	srv := serveJWKS(t, key, kid)

	audience := "/projects/123/apps/test-app"
	v := NewValidator(audience, srv.URL)

	tokenStr := makeIAPToken(t, key, "unknown-kid", audience, "user@example.com", "sub1", time.Now().Add(time.Hour))

	_, err := v.Validate(tokenStr)
	if err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

func TestValidator_WrongSigningMethod(t *testing.T) {
	audience := "/projects/123/apps/test-app"
	v := NewValidator(audience, "http://localhost:0")

	// Create HMAC token (not ES256)
	claims := jwt.MapClaims{
		"iss":   "https://cloud.google.com/iap",
		"aud":   audience,
		"email": "user@example.com",
		"sub":   "sub1",
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte("secret"))

	_, err := v.Validate(signed)
	if err == nil {
		t.Fatal("expected error for wrong signing method")
	}
}

func TestValidator_KeyCaching(t *testing.T) {
	key, kid := makeTestKey(t)

	fetchCount := 0
	x := base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes())
	jwks := jwkSet{
		Keys: []jwkKey{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: kid, Alg: "ES256", Use: "sig"}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	audience := "/projects/123/apps/test-app"
	v := NewValidator(audience, srv.URL)

	// First validation fetches keys
	t1 := makeIAPToken(t, key, kid, audience, "user@example.com", "sub1", time.Now().Add(time.Hour))
	if _, err := v.Validate(t1); err != nil {
		t.Fatalf("first validation failed: %v", err)
	}

	// Second validation should use cache
	t2 := makeIAPToken(t, key, kid, audience, "user@example.com", "sub1", time.Now().Add(time.Hour))
	if _, err := v.Validate(t2); err != nil {
		t.Fatalf("second validation failed: %v", err)
	}

	if fetchCount != 1 {
		t.Errorf("expected 1 key fetch, got %d", fetchCount)
	}
}

func TestParseECPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	jwk := jwkKey{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}

	parsed, err := parseECPublicKey(jwk)
	if err != nil {
		t.Fatalf("parsing key: %v", err)
	}

	if parsed.X.Cmp(key.PublicKey.X) != 0 || parsed.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Error("parsed key does not match original")
	}

	fmt.Println("key parsed successfully:", parsed.Curve.Params().Name)
}
