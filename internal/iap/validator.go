package iap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the validated claims from an IAP JWT.
type Claims struct {
	Subject string
	Email   string
	// Name is the optional "name" claim (human display name); may be empty.
	Name string
}

// Validator validates Google IAP JWT tokens.
type Validator struct {
	audience     string
	publicKeyURL string

	mu        sync.RWMutex
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time
	cacheTTL  time.Duration
}

// NewValidator creates a new IAP JWT validator.
func NewValidator(audience, publicKeyURL string) *Validator {
	return &Validator{
		audience:     audience,
		publicKeyURL: publicKeyURL,
		keys:         make(map[string]*ecdsa.PublicKey),
		cacheTTL:     1 * time.Hour,
	}
}

// Validate validates an IAP JWT assertion and returns the claims.
func (v *Validator) Validate(tokenString string) (*Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("missing kid in token header")
		}
		key, err := v.getKey(kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithAudience(v.audience),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid IAP token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid IAP token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate issuer
	iss, _ := claims["iss"].(string)
	if iss != "https://cloud.google.com/iap" {
		return nil, fmt.Errorf("invalid issuer: %s", iss)
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	if sub == "" || email == "" {
		return nil, fmt.Errorf("missing sub or email in IAP token")
	}

	return &Claims{
		Subject: sub,
		Email:   email,
		Name:    name,
	}, nil
}

func (v *Validator) getKey(kid string) (*ecdsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	expired := time.Since(v.fetchedAt) > v.cacheTTL
	v.mu.RUnlock()

	if ok && !expired {
		return key, nil
	}

	// Fetch fresh keys
	if err := v.fetchKeys(); err != nil {
		// If we have the key cached, use it even if expired
		if ok {
			return key, nil
		}
		return nil, fmt.Errorf("fetching IAP public keys: %w", err)
	}

	v.mu.RLock()
	key, ok = v.keys[kid]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown kid: %s", kid)
	}
	return key, nil
}

// jwkSet represents a JWK Set (JWKS).
type jwkSet struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

func (v *Validator) fetchKeys() error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(v.publicKeyURL)
	if err != nil {
		return fmt.Errorf("fetching JWK: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWK endpoint returned status %d", resp.StatusCode)
	}

	var jwks jwkSet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decoding JWK response: %w", err)
	}

	keys := make(map[string]*ecdsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		pubKey, err := parseECPublicKey(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pubKey
	}

	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()

	return nil
}

func parseECPublicKey(k jwkKey) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decoding x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decoding y: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}
