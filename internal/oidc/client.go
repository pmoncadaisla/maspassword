package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims are the identity claims extracted from a validated ID token.
type Claims struct {
	Subject string
	Email   string
	// Name is the optional "name" claim (human display name); may be empty.
	Name string
	// HostedDomain is Google's "hd" claim (Workspace domain); empty elsewhere.
	HostedDomain string
}

// Client wraps one Provider with its runtime state: the cached discovery
// document and a TTL-cached JWKS key set (same pattern as internal/iap).
type Client struct {
	Provider

	httpc *http.Client

	mu      sync.RWMutex
	disc    *discoveryDoc
	keys    map[string]*rsa.PublicKey
	keysAt  time.Time
	keysTTL time.Duration
}

func newClient(p Provider) *Client {
	return &Client{
		Provider: p,
		httpc:    &http.Client{Timeout: 10 * time.Second},
		keys:     make(map[string]*rsa.PublicKey),
		keysTTL:  1 * time.Hour,
	}
}

// discoveryDoc is the subset of .well-known/openid-configuration we need.
type discoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Endpoints resolves the authorization, token and JWKS endpoints: env
// overrides win, anything missing comes from the (cached) discovery document.
func (c *Client) Endpoints(ctx context.Context) (authURL, tokenURL, jwksURL string, err error) {
	authURL, tokenURL, jwksURL = c.AuthURLOverride, c.TokenURLOverride, c.JWKSURLOverride
	if authURL != "" && tokenURL != "" && jwksURL != "" {
		return authURL, tokenURL, jwksURL, nil
	}
	doc, err := c.discover(ctx)
	if err != nil {
		return "", "", "", err
	}
	if authURL == "" {
		authURL = doc.AuthorizationEndpoint
	}
	if tokenURL == "" {
		tokenURL = doc.TokenEndpoint
	}
	if jwksURL == "" {
		jwksURL = doc.JWKSURI
	}
	if authURL == "" || tokenURL == "" || jwksURL == "" {
		return "", "", "", fmt.Errorf("oidc %s: discovery document is missing endpoints", c.ID)
	}
	return authURL, tokenURL, jwksURL, nil
}

// discover fetches {issuer}/.well-known/openid-configuration once and caches
// it for the process lifetime.
func (c *Client) discover(ctx context.Context) (*discoveryDoc, error) {
	c.mu.RLock()
	doc := c.disc
	c.mu.RUnlock()
	if doc != nil {
		return doc, nil
	}

	wellKnown := strings.TrimSuffix(c.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc %s: building discovery request: %w", c.ID, err)
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc %s: fetching discovery document: %w", c.ID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc %s: discovery endpoint returned status %d", c.ID, resp.StatusCode)
	}
	var d discoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("oidc %s: decoding discovery document: %w", c.ID, err)
	}

	c.mu.Lock()
	c.disc = &d
	c.mu.Unlock()
	return &d, nil
}

// Exchange redeems an authorization code at the token endpoint and returns
// the raw id_token. Client authentication tries client_secret_post first and
// retries with HTTP basic auth (client_secret_basic) if the IdP answers 401.
func (c *Client) Exchange(ctx context.Context, code, redirectURI, codeVerifier string) (string, error) {
	_, tokenURL, _, err := c.Endpoints(ctx)
	if err != nil {
		return "", err
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
	}
	status, body, err := c.postForm(ctx, tokenURL, form, false)
	if err != nil {
		return "", err
	}
	switch {
	case status == http.StatusOK:
		log.Printf("oidc %s: token exchange authenticated via client_secret_post", c.ID)
	case status == http.StatusUnauthorized:
		// Some IdPs only accept client_secret_basic (RFC 6749 §2.3.1).
		basicForm := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {redirectURI},
			"code_verifier": {codeVerifier},
		}
		status, body, err = c.postForm(ctx, tokenURL, basicForm, true)
		if err != nil {
			return "", err
		}
		if status == http.StatusOK {
			log.Printf("oidc %s: token exchange authenticated via client_secret_basic", c.ID)
		}
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("oidc %s: token endpoint returned status %d", c.ID, status)
	}

	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("oidc %s: decoding token response: %w", c.ID, err)
	}
	if tr.IDToken == "" {
		return "", fmt.Errorf("oidc %s: token response has no id_token", c.ID)
	}
	return tr.IDToken, nil
}

func (c *Client) postForm(ctx context.Context, tokenURL string, form url.Values, basic bool) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, fmt.Errorf("oidc %s: building token request: %w", c.ID, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic {
		// Credentials are form-urlencoded before basic auth (RFC 6749 §2.3.1).
		req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("oidc %s: calling token endpoint: %w", c.ID, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("oidc %s: reading token response: %w", c.ID, err)
	}
	return resp.StatusCode, body, nil
}

// ValidateIDToken verifies an ID token: RS256 signature against the
// provider's JWKS, issuer, audience (must equal the client id), exp/iat and
// the nonce bound to this login attempt. It requires a verified email and
// enforces the domain allow-list, then returns the identity claims.
func (c *Client) ValidateIDToken(ctx context.Context, rawToken, expectedNonce string) (*Claims, error) {
	token, err := jwt.Parse(rawToken, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("missing kid in token header")
		}
		return c.getKey(ctx, kid)
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithAudience(c.ClientID),
		jwt.WithIssuer(c.Issuer),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid ID token: %w", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid ID token claims")
	}

	if nonce, _ := claims["nonce"].(string); nonce == "" || nonce != expectedNonce {
		return nil, fmt.Errorf("nonce mismatch")
	}

	email, _ := claims["email"].(string)
	if email == "" {
		return nil, fmt.Errorf("ID token has no email claim")
	}
	// email_verified may be a bool or a string depending on the IdP; when
	// present it must be true.
	if v, present := claims["email_verified"]; present && !truthy(v) {
		return nil, fmt.Errorf("email not verified")
	}

	out := &Claims{Email: email}
	out.Subject, _ = claims["sub"].(string)
	out.Name, _ = claims["name"].(string)
	out.HostedDomain, _ = claims["hd"].(string)

	if !domainAllowed(c.AllowedDomains, email, out.HostedDomain) {
		return nil, fmt.Errorf("email domain not allowed")
	}
	return out, nil
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	default:
		return false
	}
}

// domainAllowed enforces the allow-list: with no domains configured every
// account passes; otherwise the email's domain OR the hd claim must match.
func domainAllowed(allowed []string, email, hd string) bool {
	if len(allowed) == 0 {
		return true
	}
	domain := ""
	if at := strings.LastIndexByte(email, '@'); at >= 0 {
		domain = strings.ToLower(email[at+1:])
	}
	hd = strings.ToLower(hd)
	for _, a := range allowed {
		if a == domain || (hd != "" && a == hd) {
			return true
		}
	}
	return false
}

// getKey returns the RSA public key for a kid, refreshing the JWKS cache when
// the kid is unknown or the cache expired. A stale key beats a failed fetch.
func (c *Client) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	expired := time.Since(c.keysAt) > c.keysTTL
	c.mu.RUnlock()

	if ok && !expired {
		return key, nil
	}

	if err := c.fetchKeys(ctx); err != nil {
		if ok {
			return key, nil
		}
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}

	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()
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
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

func (c *Client) fetchKeys(ctx context.Context) error {
	_, _, jwksURL, err := c.Endpoints(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return fmt.Errorf("building JWKS request: %w", err)
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var set jwkSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("decoding JWKS response: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, err := parseRSAKey(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}

	c.mu.Lock()
	c.keys = keys
	c.keysAt = time.Now()
	c.mu.Unlock()
	return nil
}

func parseRSAKey(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, fmt.Errorf("invalid exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}
