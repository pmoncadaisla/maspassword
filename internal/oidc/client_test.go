package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "https://issuer.test"

func makeRSATestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	return key, "test-kid-1"
}

func rsaJWKS(key *rsa.PrivateKey, kid string) jwkSet {
	e := big.NewInt(int64(key.PublicKey.E))
	return jwkSet{Keys: []jwkKey{{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(e.Bytes()),
		Alg: "RS256",
		Use: "sig",
	}}}
}

func serveRSAJWKS(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	jwks := rsaJWKS(key, kid)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testClient builds a Client with endpoint overrides (no discovery needed).
func testClient(jwksURL string, allowedDomains []string) *Client {
	return newClient(Provider{
		ID:               "google",
		DisplayName:      "Google",
		Issuer:           testIssuer,
		ClientID:         "client-1",
		ClientSecret:     "secret-1",
		AuthURLOverride:  "https://auth.test/authorize",
		TokenURLOverride: "https://token.test/token",
		JWKSURLOverride:  jwksURL,
		AllowedDomains:   allowedDomains,
	})
}

func makeIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("signing ID token: %v", err)
	}
	return signed
}

func baseClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":            testIssuer,
		"aud":            "client-1",
		"sub":            "sub-42",
		"email":          "ana.perez@example.com",
		"email_verified": true,
		"name":           "Ana Pérez",
		"nonce":          "nonce-1",
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
}

func TestValidateIDToken_Valid(t *testing.T) {
	key, kid := makeRSATestKey(t)
	srv := serveRSAJWKS(t, key, kid)
	c := testClient(srv.URL, nil)

	claims := baseClaims()
	claims["hd"] = "example.com"
	got, err := c.ValidateIDToken(context.Background(), makeIDToken(t, key, kid, claims), "nonce-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Email != "ana.perez@example.com" || got.Name != "Ana Pérez" ||
		got.HostedDomain != "example.com" || got.Subject != "sub-42" {
		t.Errorf("claims mismatch: %+v", got)
	}
}

func TestValidateIDToken_WrongAudience(t *testing.T) {
	key, kid := makeRSATestKey(t)
	srv := serveRSAJWKS(t, key, kid)
	c := testClient(srv.URL, nil)

	claims := baseClaims()
	claims["aud"] = "someone-else"
	if _, err := c.ValidateIDToken(context.Background(), makeIDToken(t, key, kid, claims), "nonce-1"); err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestValidateIDToken_WrongIssuer(t *testing.T) {
	key, kid := makeRSATestKey(t)
	srv := serveRSAJWKS(t, key, kid)
	c := testClient(srv.URL, nil)

	claims := baseClaims()
	claims["iss"] = "https://evil.test"
	if _, err := c.ValidateIDToken(context.Background(), makeIDToken(t, key, kid, claims), "nonce-1"); err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestValidateIDToken_WrongNonce(t *testing.T) {
	key, kid := makeRSATestKey(t)
	srv := serveRSAJWKS(t, key, kid)
	c := testClient(srv.URL, nil)

	if _, err := c.ValidateIDToken(context.Background(), makeIDToken(t, key, kid, baseClaims()), "other-nonce"); err == nil {
		t.Fatal("expected error for nonce mismatch")
	}
}

func TestValidateIDToken_Expired(t *testing.T) {
	key, kid := makeRSATestKey(t)
	srv := serveRSAJWKS(t, key, kid)
	c := testClient(srv.URL, nil)

	claims := baseClaims()
	claims["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	if _, err := c.ValidateIDToken(context.Background(), makeIDToken(t, key, kid, claims), "nonce-1"); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestValidateIDToken_EmailNotVerified(t *testing.T) {
	key, kid := makeRSATestKey(t)
	srv := serveRSAJWKS(t, key, kid)
	c := testClient(srv.URL, nil)

	claims := baseClaims()
	claims["email_verified"] = false
	if _, err := c.ValidateIDToken(context.Background(), makeIDToken(t, key, kid, claims), "nonce-1"); err == nil {
		t.Fatal("expected error for unverified email")
	}
}

func TestValidateIDToken_EmailVerifiedVariants(t *testing.T) {
	key, kid := makeRSATestKey(t)
	srv := serveRSAJWKS(t, key, kid)
	c := testClient(srv.URL, nil)

	// String "true" (some IdPs) must pass.
	claims := baseClaims()
	claims["email_verified"] = "true"
	if _, err := c.ValidateIDToken(context.Background(), makeIDToken(t, key, kid, claims), "nonce-1"); err != nil {
		t.Fatalf("string true should pass: %v", err)
	}

	// Absent claim must pass (only required to be true when present).
	claims = baseClaims()
	delete(claims, "email_verified")
	if _, err := c.ValidateIDToken(context.Background(), makeIDToken(t, key, kid, claims), "nonce-1"); err != nil {
		t.Fatalf("absent email_verified should pass: %v", err)
	}
}

func TestValidateIDToken_MissingEmail(t *testing.T) {
	key, kid := makeRSATestKey(t)
	srv := serveRSAJWKS(t, key, kid)
	c := testClient(srv.URL, nil)

	claims := baseClaims()
	delete(claims, "email")
	if _, err := c.ValidateIDToken(context.Background(), makeIDToken(t, key, kid, claims), "nonce-1"); err == nil {
		t.Fatal("expected error for missing email")
	}
}

func TestValidateIDToken_RejectsHMAC(t *testing.T) {
	key, kid := makeRSATestKey(t)
	srv := serveRSAJWKS(t, key, kid)
	c := testClient(srv.URL, nil)
	_ = key

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims())
	token.Header["kid"] = kid
	signed, _ := token.SignedString([]byte("secret"))
	if _, err := c.ValidateIDToken(context.Background(), signed, "nonce-1"); err == nil {
		t.Fatal("expected error for HMAC-signed token")
	}
}

func TestValidateIDToken_DomainGating(t *testing.T) {
	key, kid := makeRSATestKey(t)
	srv := serveRSAJWKS(t, key, kid)

	// Email domain allowed.
	c := testClient(srv.URL, []string{"example.com"})
	if _, err := c.ValidateIDToken(context.Background(), makeIDToken(t, key, kid, baseClaims()), "nonce-1"); err != nil {
		t.Fatalf("email domain should be allowed: %v", err)
	}

	// hd claim allowed even though email domain differs.
	c = testClient(srv.URL, []string{"corp.example"})
	claims := baseClaims()
	claims["hd"] = "corp.example"
	if _, err := c.ValidateIDToken(context.Background(), makeIDToken(t, key, kid, claims), "nonce-1"); err != nil {
		t.Fatalf("hd domain should be allowed: %v", err)
	}

	// Neither matches: denied.
	c = testClient(srv.URL, []string{"other.example"})
	if _, err := c.ValidateIDToken(context.Background(), makeIDToken(t, key, kid, baseClaims()), "nonce-1"); err == nil {
		t.Fatal("expected error for domain not in allow-list")
	}
}

func TestDomainAllowed(t *testing.T) {
	cases := []struct {
		allowed []string
		email   string
		hd      string
		want    bool
	}{
		{nil, "a@x.com", "", true},                                // empty list: allow all
		{[]string{"x.com"}, "a@x.com", "", true},                  // email match
		{[]string{"x.com"}, "a@X.COM", "", true},                  // case-insensitive email
		{[]string{"x.com"}, "a@y.com", "x.com", true},             // hd match
		{[]string{"x.com"}, "a@y.com", "X.com", true},             // case-insensitive hd
		{[]string{"x.com"}, "a@y.com", "", false},                 // deny
		{[]string{"x.com", "z.com"}, "a@z.com", "", true},         // multi-entry
		{[]string{"x.com"}, "no-at-sign", "", false},              // malformed email
		{[]string{"x.com"}, "a@evil.com", "also-evil.com", false}, // both wrong
	}
	for i, tc := range cases {
		if got := domainAllowed(tc.allowed, tc.email, tc.hd); got != tc.want {
			t.Errorf("case %d: domainAllowed(%v, %q, %q) = %v, want %v", i, tc.allowed, tc.email, tc.hd, got, tc.want)
		}
	}
}

func TestJWKSCaching(t *testing.T) {
	key, kid := makeRSATestKey(t)
	jwks := rsaJWKS(key, kid)

	fetches := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	c := testClient(srv.URL, nil)
	for i := 0; i < 2; i++ {
		if _, err := c.ValidateIDToken(context.Background(), makeIDToken(t, key, kid, baseClaims()), "nonce-1"); err != nil {
			t.Fatalf("validation %d failed: %v", i, err)
		}
	}
	if fetches != 1 {
		t.Errorf("expected 1 JWKS fetch, got %d", fetches)
	}
}

func TestDiscovery_ResolvesAndCaches(t *testing.T) {
	fetches := 0
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		fetches++
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srvURL,
			"authorization_endpoint": srvURL + "/authorize",
			"token_endpoint":         srvURL + "/token",
			"jwks_uri":               srvURL + "/jwks",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	c := newClient(Provider{
		ID: "google", DisplayName: "Google", Issuer: srv.URL,
		ClientID: "client-1", ClientSecret: "secret-1",
	})

	for i := 0; i < 2; i++ {
		authURL, tokenURL, jwksURL, err := c.Endpoints(context.Background())
		if err != nil {
			t.Fatalf("endpoints: %v", err)
		}
		if authURL != srv.URL+"/authorize" || tokenURL != srv.URL+"/token" || jwksURL != srv.URL+"/jwks" {
			t.Errorf("unexpected endpoints: %s %s %s", authURL, tokenURL, jwksURL)
		}
	}
	if fetches != 1 {
		t.Errorf("expected 1 discovery fetch, got %d", fetches)
	}
}

func TestExchange_ClientSecretPost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parsing form: %v", err)
		}
		for k, want := range map[string]string{
			"grant_type":    "authorization_code",
			"code":          "code-1",
			"redirect_uri":  "https://app.test/auth/sso/google/callback",
			"code_verifier": "verifier-1",
			"client_id":     "client-1",
			"client_secret": "secret-1",
		} {
			if got := r.PostFormValue(k); got != want {
				t.Errorf("form %s = %q, want %q", k, got, want)
			}
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": "id-token-abc", "access_token": "at", "token_type": "Bearer"})
	}))
	defer srv.Close()

	c := testClient("https://jwks.test", nil)
	c.TokenURLOverride = srv.URL

	idToken, err := c.Exchange(context.Background(), "code-1", "https://app.test/auth/sso/google/callback", "verifier-1")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if idToken != "id-token-abc" {
		t.Errorf("id_token = %q", idToken)
	}
}

func TestExchange_RetriesWithBasicAuth(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		user, pass, ok := r.BasicAuth()
		if !ok {
			// First attempt (client_secret_post): reject.
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if user != url.QueryEscape("client-1") || pass != url.QueryEscape("secret-1") {
			t.Errorf("basic auth = %q:%q", user, pass)
		}
		if r.PostFormValue("client_secret") != "" {
			t.Error("basic-auth retry must not carry client_secret in the form")
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": "id-token-basic"})
	}))
	defer srv.Close()

	c := testClient("https://jwks.test", nil)
	c.TokenURLOverride = srv.URL

	idToken, err := c.Exchange(context.Background(), "code-1", "https://app.test/cb", "verifier-1")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if idToken != "id-token-basic" {
		t.Errorf("id_token = %q", idToken)
	}
	if requests != 2 {
		t.Errorf("expected 2 requests (post then basic), got %d", requests)
	}
}

func TestExchange_HardFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	c := testClient("https://jwks.test", nil)
	c.TokenURLOverride = srv.URL

	if _, err := c.Exchange(context.Background(), "bad-code", "https://app.test/cb", "v"); err == nil {
		t.Fatal("expected error for token endpoint failure")
	}
}

func TestRegistry_ListAndGet(t *testing.T) {
	r := NewRegistry([]Provider{
		{ID: "google", DisplayName: "Google", Issuer: testIssuer, ClientID: "a", ClientSecret: "b"},
	})
	list := r.List()
	if len(list) != 1 || list[0].ID != "google" || list[0].Name != "Google" {
		t.Errorf("unexpected list: %+v", list)
	}
	if _, ok := r.Get("google"); !ok {
		t.Error("google should resolve")
	}
	if _, ok := r.Get("okta"); ok {
		t.Error("okta should not resolve")
	}
	if r.Empty() {
		t.Error("registry should not be empty")
	}

	empty := NewRegistry(nil)
	if !empty.Empty() {
		t.Error("nil registry should be empty")
	}
	if got := empty.List(); got == nil || len(got) != 0 {
		t.Errorf("empty registry List() must be a non-nil empty slice, got %#v", got)
	}
}

func TestRegistryFromEnv(t *testing.T) {
	t.Setenv("OIDC_GOOGLE_CLIENT_ID", "cid")
	t.Setenv("OIDC_GOOGLE_CLIENT_SECRET", "csecret")
	t.Setenv("OIDC_ALLOWED_DOMAINS", " Example.com, @corp.example ,")

	r := RegistryFromEnv()
	c, ok := r.Get("google")
	if !ok {
		t.Fatal("google provider should be registered")
	}
	if c.Issuer != "https://accounts.google.com" {
		t.Errorf("default issuer = %q", c.Issuer)
	}
	if len(c.AllowedDomains) != 2 || c.AllowedDomains[0] != "example.com" || c.AllowedDomains[1] != "corp.example" {
		t.Errorf("allowed domains = %v", c.AllowedDomains)
	}

	// Overrides + custom issuer.
	t.Setenv("OIDC_GOOGLE_ISSUER", "https://custom.issuer/")
	t.Setenv("OIDC_GOOGLE_AUTH_URL", "https://custom.issuer/auth")
	t.Setenv("OIDC_GOOGLE_TOKEN_URL", "https://custom.issuer/token")
	t.Setenv("OIDC_GOOGLE_JWKS_URL", "https://custom.issuer/jwks")
	r = RegistryFromEnv()
	c, _ = r.Get("google")
	if c.Issuer != "https://custom.issuer" {
		t.Errorf("custom issuer = %q (trailing slash should be trimmed)", c.Issuer)
	}
	a, tk, j, err := c.Endpoints(context.Background())
	if err != nil || a != "https://custom.issuer/auth" || tk != "https://custom.issuer/token" || j != "https://custom.issuer/jwks" {
		t.Errorf("override endpoints = %s %s %s (%v)", a, tk, j, err)
	}

	// Without a secret, the provider is not registered.
	t.Setenv("OIDC_GOOGLE_CLIENT_SECRET", "")
	if r := RegistryFromEnv(); !r.Empty() {
		t.Error("provider must not register without a client secret")
	}
}
