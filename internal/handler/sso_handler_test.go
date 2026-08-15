package handler

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
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/oidc"
	"github.com/masorange/maspassword/internal/repository"
)

const (
	ssoTestSecret = "sso-test-jwt-secret"
	ssoTestIssuer = "https://issuer.test"
)

// --- In-memory UserRepository (same shape as the middleware test mock) ---

type fakeUserRepo struct {
	mu    sync.Mutex
	users map[string]*models.User
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{users: make(map[string]*models.User)}
}

func (m *fakeUserRepo) Create(_ context.Context, user *models.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	user.ID = uuid.New()
	m.users[user.Email] = user
	return nil
}

func (m *fakeUserRepo) GetByID(_ context.Context, id uuid.UUID) (*models.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, repository.ErrUserNotFound
}

func (m *fakeUserRepo) GetByEmail(_ context.Context, email string) (*models.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[email]; ok {
		return u, nil
	}
	return nil, repository.ErrUserNotFound
}

func (m *fakeUserRepo) FindOrCreateByEmail(_ context.Context, email string) (*models.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[email]; ok {
		return u, nil
	}
	u := &models.User{ID: uuid.New(), Email: email}
	m.users[email] = u
	return u, nil
}

func (m *fakeUserRepo) UpdateKeys(_ context.Context, _ uuid.UUID, _, _ string) error { return nil }
func (m *fakeUserRepo) UpdateSRPCredentials(_ context.Context, _ uuid.UUID, _, _ string) error {
	return nil
}
func (m *fakeUserRepo) UpdateRecoveryKey(_ context.Context, _ uuid.UUID, _ string) error { return nil }
func (m *fakeUserRepo) UpdateFullCredentials(_ context.Context, _ uuid.UUID, _, _, _, _ string) error {
	return nil
}

func (m *fakeUserRepo) UpdateDisplayName(_ context.Context, id uuid.UUID, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.ID == id {
			u.DisplayName = name
			return nil
		}
	}
	return repository.ErrUserNotFound
}

func (m *fakeUserRepo) GetPublicKey(_ context.Context, _ uuid.UUID) (string, error) { return "", nil }
func (m *fakeUserRepo) GetPublicKeysByIDs(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]string, error) {
	return nil, nil
}

// --- SSO test environment: JWKS + token endpoint + router with SSO routes ---

type ssoTestEnv struct {
	router   *gin.Engine
	handler  *SSOHandler
	userRepo *fakeUserRepo
	key      *rsa.PrivateKey
	kid      string

	// idClaims is used by the token endpoint to mint the id_token returned
	// for the next exchange. Tests mutate it before hitting the callback.
	mu       sync.Mutex
	idClaims jwt.MapClaims
}

func (e *ssoTestEnv) setClaims(c jwt.MapClaims) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.idClaims = c
}

func (e *ssoTestEnv) signIDToken(t *testing.T) string {
	t.Helper()
	e.mu.Lock()
	claims := e.idClaims
	e.mu.Unlock()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = e.kid
	signed, err := token.SignedString(e.key)
	if err != nil {
		t.Fatalf("signing id_token: %v", err)
	}
	return signed
}

func newSSOTestEnv(t *testing.T, allowedDomains []string) *ssoTestEnv {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	env := &ssoTestEnv{key: key, kid: "sso-test-kid", userRepo: newFakeUserRepo()}

	// JWKS endpoint
	eBytes := big.NewInt(int64(key.PublicKey.E)).Bytes()
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": env.kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
		"alg": "RS256",
		"use": "sig",
	}}}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(jwksSrv.Close)

	// Token endpoint: accepts client_secret_post and returns an id_token
	// minted from env.idClaims.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("client_secret") != "secret-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": env.signIDToken(t)})
	}))
	t.Cleanup(tokenSrv.Close)

	registry := oidc.NewRegistry([]oidc.Provider{{
		ID:               "google",
		DisplayName:      "Google",
		Issuer:           ssoTestIssuer,
		ClientID:         "client-1",
		ClientSecret:     "secret-1",
		AuthURLOverride:  "https://auth.test/authorize",
		TokenURLOverride: tokenSrv.URL,
		JWKSURLOverride:  jwksSrv.URL,
		AllowedDomains:   allowedDomains,
	}})

	env.handler = NewSSOHandler(registry, ssoTestSecret, "", env.userRepo)

	// Same route shapes as the real router (static + :provider siblings).
	r := gin.New()
	r.GET("/auth/sso/providers", env.handler.Providers)
	r.GET("/auth/sso/:provider/start", env.handler.Start)
	r.GET("/auth/sso/:provider/callback", env.handler.Callback)
	env.router = r

	return env
}

// startFlow performs /start and returns the state parameter sent to the IdP
// plus the parsed state claims.
func (e *ssoTestEnv) startFlow(t *testing.T) (stateParam string, state *oidc.State) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/google/start", nil)
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("start: expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	q := loc.Query()
	stateParam = q.Get("state")
	state, err = oidc.ParseState([]byte(ssoTestSecret), stateParam)
	if err != nil {
		t.Fatalf("parsing state: %v", err)
	}
	return stateParam, state
}

func validClaims(nonce string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":            ssoTestIssuer,
		"aud":            "client-1",
		"sub":            "sub-1",
		"email":          "ana.perez@example.com",
		"email_verified": true,
		"name":           "Ana Pérez",
		"nonce":          nonce,
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
}

// --- Tests ---

func TestSSO_StartRedirectsWithPKCEAndState(t *testing.T) {
	env := newSSOTestEnv(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/sso/google/start", nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != "https://auth.test/authorize" {
		t.Errorf("authorization endpoint = %s", got)
	}

	q := loc.Query()
	if q.Get("client_id") != "client-1" || q.Get("response_type") != "code" ||
		q.Get("scope") != "openid email profile" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("unexpected auth params: %v", q)
	}
	// httptest requests carry Host example.com; no APP_BASE_URL configured.
	if got := q.Get("redirect_uri"); got != "http://example.com/auth/sso/google/callback" {
		t.Errorf("redirect_uri = %s", got)
	}

	state, err := oidc.ParseState([]byte(ssoTestSecret), q.Get("state"))
	if err != nil {
		t.Fatalf("state must verify with the app secret: %v", err)
	}
	if state.Provider != "google" {
		t.Errorf("state provider = %s", state.Provider)
	}
	if q.Get("nonce") != state.Nonce {
		t.Error("nonce param must match the nonce inside the state")
	}
	if q.Get("code_challenge") != oidc.CodeChallengeS256(state.CodeVerifier) {
		t.Error("code_challenge must be the S256 hash of the state's code_verifier")
	}
}

func TestSSO_StartHonorsForwardedProtoAndBaseURL(t *testing.T) {
	env := newSSOTestEnv(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/sso/google/start", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if got := loc.Query().Get("redirect_uri"); got != "https://example.com/auth/sso/google/callback" {
		t.Errorf("redirect_uri with X-Forwarded-Proto = %s", got)
	}

	env.handler.appBaseURL = "https://vault.corp.example"
	w = httptest.NewRecorder()
	env.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/sso/google/start", nil))
	loc, _ = url.Parse(w.Header().Get("Location"))
	if got := loc.Query().Get("redirect_uri"); got != "https://vault.corp.example/auth/sso/google/callback" {
		t.Errorf("redirect_uri with APP_BASE_URL = %s", got)
	}
}

func TestSSO_CallbackHappyPath(t *testing.T) {
	env := newSSOTestEnv(t, nil)
	stateParam, state := env.startFlow(t)
	env.setClaims(validClaims(state.Nonce))

	req := httptest.NewRequest(http.MethodGet,
		"/auth/sso/google/callback?code=code-1&state="+url.QueryEscape(stateParam), nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "/app#sso=") {
		t.Fatalf("callback page must hand the token via /app#sso=, got: %s", body)
	}

	// Extract the JSON string literal passed to encodeURIComponent and check
	// it is the standard session JWT (user_id claim, app secret, HS256).
	m := regexp.MustCompile(`encodeURIComponent\(("[^"]+")\)`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("could not find token in callback page: %s", body)
	}
	var sessionToken string
	if err := json.Unmarshal([]byte(m[1]), &sessionToken); err != nil {
		t.Fatalf("token is not a JSON string: %v", err)
	}
	parsed, err := jwt.Parse(sessionToken, func(tk *jwt.Token) (any, error) {
		if _, ok := tk.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(ssoTestSecret), nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("session token invalid: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)

	user, err := env.userRepo.GetByEmail(context.Background(), "ana.perez@example.com")
	if err != nil {
		t.Fatal("user must have been auto-provisioned")
	}
	if claims["user_id"] != user.ID.String() {
		t.Errorf("token user_id = %v, want %s", claims["user_id"], user.ID)
	}
	if user.DisplayName != "Ana Pérez" {
		t.Errorf("display name = %q, want backfill from the name claim", user.DisplayName)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("callback must not be cacheable, got %q", cc)
	}
}

func TestSSO_CallbackNonceMismatch(t *testing.T) {
	env := newSSOTestEnv(t, nil)
	stateParam, _ := env.startFlow(t)
	env.setClaims(validClaims("a-different-nonce"))

	req := httptest.NewRequest(http.MethodGet,
		"/auth/sso/google/callback?code=code-1&state="+url.QueryEscape(stateParam), nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for nonce mismatch, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "#sso=") {
		t.Error("no token must be issued on nonce mismatch")
	}
}

func TestSSO_CallbackWrongAudience(t *testing.T) {
	env := newSSOTestEnv(t, nil)
	stateParam, state := env.startFlow(t)
	claims := validClaims(state.Nonce)
	claims["aud"] = "another-client"
	env.setClaims(claims)

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/auth/sso/google/callback?code=c&state="+url.QueryEscape(stateParam), nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong audience, got %d", w.Code)
	}
}

func TestSSO_CallbackWrongIssuer(t *testing.T) {
	env := newSSOTestEnv(t, nil)
	stateParam, state := env.startFlow(t)
	claims := validClaims(state.Nonce)
	claims["iss"] = "https://evil.test"
	env.setClaims(claims)

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/auth/sso/google/callback?code=c&state="+url.QueryEscape(stateParam), nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong issuer, got %d", w.Code)
	}
}

func TestSSO_CallbackTamperedState(t *testing.T) {
	env := newSSOTestEnv(t, nil)
	stateParam, _ := env.startFlow(t)
	tampered := stateParam[:len(stateParam)-2] + "xx"

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/auth/sso/google/callback?code=c&state="+url.QueryEscape(tampered), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for tampered state, got %d", w.Code)
	}
}

func TestSSO_CallbackProviderMismatch(t *testing.T) {
	env := newSSOTestEnv(t, nil)

	// State signed for a different provider id must be rejected.
	stateParam, err := oidc.SignState([]byte(ssoTestSecret), oidc.State{
		Provider: "okta", Nonce: "n", CodeVerifier: "v", RedirectURI: "http://example.com/cb",
	})
	if err != nil {
		t.Fatalf("signing state: %v", err)
	}
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/auth/sso/google/callback?code=c&state="+url.QueryEscape(stateParam), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for provider mismatch, got %d", w.Code)
	}
}

func TestSSO_CallbackDomainDenied(t *testing.T) {
	env := newSSOTestEnv(t, []string{"corp.example"})
	stateParam, state := env.startFlow(t)
	env.setClaims(validClaims(state.Nonce)) // email is @example.com → denied

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/auth/sso/google/callback?code=c&state="+url.QueryEscape(stateParam), nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for domain not allowed, got %d", w.Code)
	}
	if _, err := env.userRepo.GetByEmail(context.Background(), "ana.perez@example.com"); err == nil {
		t.Error("no user must be provisioned for a denied domain")
	}
}

func TestSSO_CallbackIdPError(t *testing.T) {
	env := newSSOTestEnv(t, nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/auth/sso/google/callback?error=access_denied", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for IdP error param, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "access_denied") {
		t.Error("error page should mention the IdP error code")
	}
}

func TestSSO_UnknownProvider(t *testing.T) {
	env := newSSOTestEnv(t, nil)
	for _, path := range []string{"/auth/sso/okta/start", "/auth/sso/okta/callback?code=c&state=s"} {
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: expected 404, got %d", path, w.Code)
		}
	}
}

// The /auth/sso/providers static route must coexist with the :provider
// wildcard siblings (gin supports this since v1.7) and return the list.
func TestSSO_ProvidersEndpoint(t *testing.T) {
	env := newSSOTestEnv(t, nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/sso/providers", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var list []oidc.ProviderInfo
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decoding providers: %v", err)
	}
	if len(list) != 1 || list[0].ID != "google" || list[0].Name != "Google" {
		t.Errorf("unexpected providers: %+v", list)
	}
}

// Extension flow: /start?ext_redirect=<chromiumapp.org URL> makes the
// callback 302 the session token to the extension via the URL fragment.
func TestSSO_ExtensionRedirect(t *testing.T) {
	env := newSSOTestEnv(t, nil)
	extURL := "https://" + strings.Repeat("a", 32) + ".chromiumapp.org/sso"

	req := httptest.NewRequest(http.MethodGet,
		"/auth/sso/google/start?ext_redirect="+url.QueryEscape(extURL), nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("start with ext_redirect: expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	stateParam := loc.Query().Get("state")
	state, err := oidc.ParseState([]byte(ssoTestSecret), stateParam)
	if err != nil {
		t.Fatalf("parsing state: %v", err)
	}
	if state.ExtRedirect != extURL {
		t.Fatalf("state ext_redirect = %q, want %q", state.ExtRedirect, extURL)
	}

	env.setClaims(validClaims(state.Nonce))
	w = httptest.NewRecorder()
	env.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/auth/sso/google/callback?code=code-1&state="+url.QueryEscape(stateParam), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("callback with ext_redirect: expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	target := w.Header().Get("Location")
	if !strings.HasPrefix(target, extURL+"#sso=") {
		t.Fatalf("callback Location = %q, want prefix %q", target, extURL+"#sso=")
	}
	sessionToken, _ := url.QueryUnescape(strings.TrimPrefix(target, extURL+"#sso="))
	parsed, err := jwt.Parse(sessionToken, func(tk *jwt.Token) (any, error) {
		if _, ok := tk.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(ssoTestSecret), nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("session token in fragment invalid: %v", err)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("extension callback must not be cacheable, got %q", cc)
	}
}

// Anything that is not a chromiumapp.org extension origin is rejected before
// the flow even starts — no open redirect for session tokens.
func TestSSO_ExtensionRedirectRejectsForeignURLs(t *testing.T) {
	env := newSSOTestEnv(t, nil)
	for _, bad := range []string{
		"https://evil.example/steal",
		"http://" + strings.Repeat("a", 32) + ".chromiumapp.org/sso", // http, not https
		"https://" + strings.Repeat("a", 32) + ".chromiumapp.org.evil.example/",
		"https://" + strings.Repeat("A", 32) + ".chromiumapp.org/",  // uppercase not in a-p
		"https://" + strings.Repeat("a", 31) + ".chromiumapp.org/",  // wrong length
		"https://" + strings.Repeat("a", 32) + ".chromiumapp.org/x?y=1", // query not allowed
	} {
		req := httptest.NewRequest(http.MethodGet,
			"/auth/sso/google/start?ext_redirect="+url.QueryEscape(bad), nil)
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("ext_redirect %q: expected 400, got %d", bad, w.Code)
		}
	}
}
