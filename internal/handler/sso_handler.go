package handler

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/masorange/maspassword/internal/names"
	"github.com/masorange/maspassword/internal/oidc"
	"github.com/masorange/maspassword/internal/repository"
	"github.com/masorange/maspassword/internal/service"
)

// SSOHandler implements the app-level OIDC login flow under /auth/sso.
// It is provider-agnostic: everything specific to an IdP lives in the
// oidc.Registry configuration.
type SSOHandler struct {
	registry   *oidc.Registry
	jwtSecret  []byte
	appBaseURL string
	userRepo   repository.UserRepository
}

func NewSSOHandler(registry *oidc.Registry, jwtSecret, appBaseURL string, userRepo repository.UserRepository) *SSOHandler {
	return &SSOHandler{
		registry:   registry,
		jwtSecret:  []byte(jwtSecret),
		appBaseURL: strings.TrimSuffix(appBaseURL, "/"),
		userRepo:   userRepo,
	}
}

// ProviderList exposes the configured providers (embedded in /auth/mode).
func (h *SSOHandler) ProviderList() []oidc.ProviderInfo { return h.registry.List() }

// Providers handles GET /auth/sso/providers.
func (h *SSOHandler) Providers(c *gin.Context) {
	c.JSON(http.StatusOK, h.registry.List())
}

// baseURL resolves the externally visible base URL: APP_BASE_URL when set,
// otherwise scheme+host from the request (honoring X-Forwarded-Proto, since
// Cloud Run terminates TLS in front of us).
func (h *SSOHandler) baseURL(c *gin.Context) string {
	if h.appBaseURL != "" {
		return h.appBaseURL
	}
	scheme := "http"
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if c.Request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host
}

// Start handles GET /auth/sso/:provider/start — 302 to the IdP's
// authorization endpoint (authorization-code flow with PKCE S256). The whole
// round-trip context (nonce, code_verifier, redirect_uri) travels inside the
// signed state JWT; no server-side session is stored.
func (h *SSOHandler) Start(c *gin.Context) {
	client, ok := h.registry.Get(c.Param("provider"))
	if !ok {
		h.errorPage(c, http.StatusNotFound, "Unknown SSO provider.")
		return
	}
	authURL, _, _, err := client.Endpoints(c.Request.Context())
	if err != nil {
		log.Printf("sso %s: resolving endpoints: %v", client.ID, err)
		h.errorPage(c, http.StatusBadGateway, "The identity provider is not reachable right now.")
		return
	}

	nonce, err := oidc.NewNonce()
	if err != nil {
		h.errorPage(c, http.StatusInternalServerError, "Could not start the sign-in flow.")
		return
	}
	verifier, err := oidc.NewCodeVerifier()
	if err != nil {
		h.errorPage(c, http.StatusInternalServerError, "Could not start the sign-in flow.")
		return
	}

	redirectURI := h.baseURL(c) + "/auth/sso/" + url.PathEscape(client.ID) + "/callback"
	state, err := oidc.SignState(h.jwtSecret, oidc.State{
		Provider:     client.ID,
		Nonce:        nonce,
		CodeVerifier: verifier,
		RedirectURI:  redirectURI,
	})
	if err != nil {
		h.errorPage(c, http.StatusInternalServerError, "Could not start the sign-in flow.")
		return
	}

	q := url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {oidc.CodeChallengeS256(verifier)},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(authURL, "?") {
		sep = "&"
	}
	c.Redirect(http.StatusFound, authURL+sep+q.Encode())
}

// Callback handles GET /auth/sso/:provider/callback — verifies the state,
// exchanges the code, validates the ID token, finds or creates the user
// (same auto-provisioning as the IAP path) and hands the standard session
// JWT to the SPA via the URL fragment (never a query parameter, so the token
// stays out of server and proxy logs).
func (h *SSOHandler) Callback(c *gin.Context) {
	providerID := c.Param("provider")
	client, ok := h.registry.Get(providerID)
	if !ok {
		h.errorPage(c, http.StatusNotFound, "Unknown SSO provider.")
		return
	}
	if errParam := c.Query("error"); errParam != "" {
		// e.g. access_denied when the user cancels the consent screen.
		h.errorPage(c, http.StatusBadRequest, "Sign-in was cancelled or rejected ("+errParam+").")
		return
	}
	code := c.Query("code")
	stateParam := c.Query("state")
	if code == "" || stateParam == "" {
		h.errorPage(c, http.StatusBadRequest, "Missing code or state parameter.")
		return
	}

	state, err := oidc.ParseState(h.jwtSecret, stateParam)
	if err != nil {
		h.errorPage(c, http.StatusBadRequest, "The sign-in request is invalid or has expired. Please try again.")
		return
	}
	if state.Provider != providerID {
		h.errorPage(c, http.StatusBadRequest, "The sign-in request does not match this provider.")
		return
	}

	idToken, err := client.Exchange(c.Request.Context(), code, state.RedirectURI, state.CodeVerifier)
	if err != nil {
		log.Printf("sso %s: code exchange failed: %v", providerID, err)
		h.errorPage(c, http.StatusBadGateway, "Could not complete sign-in with the identity provider.")
		return
	}

	claims, err := client.ValidateIDToken(c.Request.Context(), idToken, state.Nonce)
	if err != nil {
		log.Printf("sso %s: ID token rejected: %v", providerID, err)
		h.errorPage(c, http.StatusUnauthorized, "Your identity could not be verified.")
		return
	}

	user, err := h.userRepo.FindOrCreateByEmail(c.Request.Context(), claims.Email)
	if err != nil {
		log.Printf("sso %s: find-or-create %s: %v", providerID, claims.Email, err)
		h.errorPage(c, http.StatusInternalServerError, "Could not resolve your account.")
		return
	}

	// Backfill the display name once: prefer the IdP "name" claim, otherwise
	// derive it from the email local part (same policy as the IAP path).
	if user.DisplayName == "" {
		name := strings.TrimSpace(claims.Name)
		if name == "" {
			name = names.DeriveFromEmail(claims.Email)
		}
		if name != "" {
			if err := h.userRepo.UpdateDisplayName(c.Request.Context(), user.ID, name); err != nil {
				log.Printf("sso %s: failed to set display name for %s: %v", providerID, claims.Email, err)
			}
		}
	}

	token, err := service.IssueSessionJWT(h.jwtSecret, user.ID)
	if err != nil {
		log.Printf("sso %s: issuing session token: %v", providerID, err)
		h.errorPage(c, http.StatusInternalServerError, "Could not create your session.")
		return
	}

	tokenJS, err := json.Marshal(token) // safe JS string literal
	if err != nil {
		h.errorPage(c, http.StatusInternalServerError, "Could not create your session.")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(fmt.Sprintf(callbackPage, tokenJS)))
}

// callbackPage hands the session token to the SPA via the URL fragment.
const callbackPage = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>MasPassword</title></head>
<body><script>location.replace('/app#sso=' + encodeURIComponent(%s));</script>
<noscript><a href="/app">Continue to MasPassword</a></noscript></body></html>`

// errorPage renders a minimal self-contained error page (no stack traces)
// with a link back to the app.
func (h *SSOHandler) errorPage(c *gin.Context, status int, msg string) {
	c.Header("Cache-Control", "no-store")
	c.Data(status, "text/html; charset=utf-8", []byte(fmt.Sprintf(errorPage, html.EscapeString(msg))))
}

const errorPage = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MasPassword — sign-in error</title></head>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem">
<h1 style="font-size:1.2rem">Could not sign you in</h1>
<p>%s</p>
<p><a href="/app">Back to MasPassword</a></p>
</body></html>`
