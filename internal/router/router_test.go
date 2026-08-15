package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/masorange/maspassword/internal/handler"
	"github.com/masorange/maspassword/internal/oidc"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// setupTestRouter builds the REAL route tree with inert handlers. Gin panics
// at registration time on conflicting routes (e.g. /auth/sso/providers vs
// /auth/sso/:provider/*), so simply constructing it is half the test.
func setupTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	// Static file routes resolve web/* relative to the working directory.
	t.Chdir("../..")

	registry := oidc.NewRegistry([]oidc.Provider{{
		ID:           "google",
		DisplayName:  "Google",
		Issuer:       "https://issuer.test",
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		// Overrides: no discovery network access in tests.
		AuthURLOverride:  "https://auth.test/authorize",
		TokenURLOverride: "https://auth.test/token",
		JWKSURLOverride:  "https://auth.test/jwks",
	}})
	ssoHandler := handler.NewSSOHandler(registry, "router-test-secret", "", nil)
	passkeyHandler := handler.NewPasskeyHandler(nil, "router-test-secret", "")

	return Setup(
		handler.NewAuthHandler(nil),
		handler.NewVaultHandler(nil),
		handler.NewItemHandler(nil),
		handler.NewTeamHandler(nil),
		handler.NewUserHandler(nil),
		handler.NewShareLinkHandler(nil),
		handler.NewSettingsHandler(nil), // DefaultTheme is nil-safe
		handler.NewDeviceHandler(nil),
		ssoHandler,
		passkeyHandler,
		nil, // deviceRepo (middleware only runs on /api)
		"router-test-secret",
		"*",
		false, // iapEnabled
		nil,   // iapValidator
		nil,   // userRepo
		nil,   // adminEmails
		false, // signupEnabled (SSO-only deployment)
		false, // passwordLoginEnabled (SSO-only deployment)
		"test-version",
	)
}

func get(r *gin.Engine, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func TestRouter_LandingAppAndSSORoutes(t *testing.T) {
	r := setupTestRouter(t)

	// "/" serves the landing page.
	w := get(r, "/")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Sésamo") {
		t.Errorf("GET / = %d, want landing page", w.Code)
	}
	// The landing must carry the bounce script for returning users.
	if !strings.Contains(w.Body.String(), "location.replace('/app'") {
		t.Error("landing page must bounce returning users to /app")
	}

	// "/app" serves the SPA.
	w = get(r, "/app")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `id="screen-login"`) {
		t.Errorf("GET /app = %d, want the app shell", w.Code)
	}

	// Legacy "/index.html" keeps pointing at the app.
	w = get(r, "/index.html")
	if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "/app" {
		t.Errorf("GET /index.html = %d %q, want 301 /app", w.Code, w.Header().Get("Location"))
	}

	// "/landing" permanently redirects to "/".
	w = get(r, "/landing")
	if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "/" {
		t.Errorf("GET /landing = %d %q, want 301 /", w.Code, w.Header().Get("Location"))
	}

	// SPA deep links still fall back to the app shell.
	w = get(r, "/some/unknown/path")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `id="screen-login"`) {
		t.Errorf("NoRoute fallback = %d, want the app shell", w.Code)
	}

	// /auth/mode exposes sso_providers and signup_enabled.
	w = get(r, "/auth/mode")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /auth/mode = %d", w.Code)
	}
	var mode struct {
		IAPEnabled    bool                `json:"iap_enabled"`
		SSOProviders  []oidc.ProviderInfo `json:"sso_providers"`
		SignupEnabled bool                `json:"signup_enabled"`
		PasswordLogin bool                `json:"password_login"`
		Version       string              `json:"version"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &mode); err != nil {
		t.Fatalf("decoding /auth/mode: %v", err)
	}
	if len(mode.SSOProviders) != 1 || mode.SSOProviders[0].ID != "google" {
		t.Errorf("sso_providers = %+v", mode.SSOProviders)
	}
	if mode.SignupEnabled {
		t.Error("signup_enabled should be false")
	}
	if mode.PasswordLogin {
		t.Error("password_login should be false")
	}
	if mode.Version != "test-version" {
		t.Errorf("version = %q", mode.Version)
	}

	// The static /auth/sso/providers leaf coexists with :provider wildcards.
	w = get(r, "/auth/sso/providers")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"google"`) {
		t.Errorf("GET /auth/sso/providers = %d (%s)", w.Code, w.Body.String())
	}

	// /auth/sso/google/start issues the IdP redirect (no discovery needed).
	w = get(r, "/auth/sso/google/start")
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "https://auth.test/authorize?") {
		t.Errorf("GET /auth/sso/google/start = %d %q", w.Code, w.Header().Get("Location"))
	}

	// Signup disabled → 403 with the documented body.
	wPost := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(wPost, req)
	if wPost.Code != http.StatusForbidden || !strings.Contains(wPost.Body.String(), "signup disabled") {
		t.Errorf("POST /auth/signup = %d (%s), want 403 signup disabled", wPost.Code, wPost.Body.String())
	}

	// Password login disabled → both SRP steps are closed, so nobody can
	// probe SRP against arbitrary emails on an SSO-only deployment.
	for _, path := range []string{"/auth/login/step1", "/auth/login/step2"} {
		wPost = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(wPost, req)
		if wPost.Code != http.StatusForbidden || !strings.Contains(wPost.Body.String(), "PASSWORD_LOGIN_DISABLED") {
			t.Errorf("POST %s = %d (%s), want 403 PASSWORD_LOGIN_DISABLED", path, wPost.Code, wPost.Body.String())
		}
	}
}
