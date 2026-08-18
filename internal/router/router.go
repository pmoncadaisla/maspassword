package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/masorange/maspassword/internal/config"
	"github.com/masorange/maspassword/internal/handler"
	"github.com/masorange/maspassword/internal/iap"
	"github.com/masorange/maspassword/internal/middleware"
	"github.com/masorange/maspassword/internal/repository"
)

func Setup(
	authHandler *handler.AuthHandler,
	vaultHandler *handler.VaultHandler,
	itemHandler *handler.ItemHandler,
	teamHandler *handler.TeamHandler,
	userHandler *handler.UserHandler,
	shareLinkHandler *handler.ShareLinkHandler,
	settingsHandler *handler.SettingsHandler,
	deviceHandler *handler.DeviceHandler,
	ssoHandler *handler.SSOHandler,
	passkeyHandler *handler.PasskeyHandler,
	deviceRepo repository.DeviceTokenRepository,
	jwtSecret string,
	corsOrigins string,
	iapEnabled bool,
	iapValidator *iap.Validator,
	userRepo repository.UserRepository,
	adminEmails config.AdminEmails,
	signupEnabled bool,
	passwordLoginEnabled bool,
	version string,
) *gin.Engine {
	r := gin.New()

	r.Use(middleware.ErrorHandler())
	r.Use(middleware.Logger())
	r.Use(middleware.CORS(corsOrigins))

	// Keep the signup/password-login toggles and the /auth/mode advertisement
	// in sync: the router is the single source of truth for both.
	authHandler.SetSignupEnabled(signupEnabled)
	authHandler.SetPasswordLoginEnabled(passwordLoginEnabled)

	// Public routes (no JWT)
	auth := r.Group("/auth")
	{
		auth.POST("/signup", authHandler.Signup)
		auth.POST("/login/step1", authHandler.LoginStep1)
		auth.POST("/login/step2", authHandler.LoginStep2)
		auth.GET("/mode", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"iap_enabled":    iapEnabled,
				"sso_providers":  ssoHandler.ProviderList(),
				"signup_enabled": signupEnabled,
				"password_login": passwordLoginEnabled,
				"passkey_login":  true,
				"version":        version,
				"default_theme":  settingsHandler.DefaultTheme(c.Request.Context()),
			})
		})

		// App-level SSO (OIDC authorization-code + PKCE)
		auth.GET("/sso/providers", ssoHandler.Providers)
		auth.GET("/sso/:provider/start", ssoHandler.Start)
		auth.GET("/sso/:provider/callback", ssoHandler.Callback)

		// Passkey login (WebAuthn assertion + PRF-wrapped keys)
		auth.POST("/passkey/challenge", passkeyHandler.Challenge)
		auth.POST("/passkey/login", passkeyHandler.Login)
		auth.GET("/recovery/:email", authHandler.GetRecoveryData)
		auth.POST("/recover/challenge", authHandler.RecoverChallenge)
		auth.POST("/recover", authHandler.Recover)

		// One-time share links (PUBLIC: recipients have no account).
		auth.POST("/share-links/:id/redeem", shareLinkHandler.Redeem)
		auth.GET("/share-links/:id/status", shareLinkHandler.Status)
	}

	// Choose auth middleware based on IAP config
	var authMiddleware gin.HandlerFunc
	if iapValidator != nil {
		authMiddleware = middleware.DualAuth(jwtSecret, iapValidator, userRepo)
	} else {
		authMiddleware = middleware.JWTAuth(jwtSecret)
	}
	// Device tokens (mpd_*) take priority; anything else falls through to JWT/IAP.
	authMiddleware = middleware.DeviceTokenAuth(deviceRepo, authMiddleware)

	// Protected routes
	api := r.Group("/api")
	api.Use(authMiddleware)
	{
		// Auth session (for IAP flow)
		api.GET("/auth/session", authHandler.GetSession)
		api.POST("/auth/setup-encryption", authHandler.SetupEncryption)

		// Login passkeys (management; registration is attestation-free
		// because it happens over an authenticated session)
		api.GET("/auth/passkeys", passkeyHandler.List)
		api.POST("/auth/passkeys", passkeyHandler.Register)
		api.DELETE("/auth/passkeys/:id", passkeyHandler.Delete)

		// Vaults
		api.GET("/vaults", vaultHandler.List)
		api.POST("/vaults", vaultHandler.Create)
		api.DELETE("/vaults/:id", vaultHandler.Delete)
		api.GET("/vaults/:id/key", vaultHandler.GetVaultKey)
		api.POST("/vaults/:id/share", vaultHandler.ShareVault)
		api.GET("/vaults/:id/shares", vaultHandler.ListShares)

		// Items
		api.GET("/vaults/:id/items", itemHandler.List)
		api.POST("/vaults/:id/items", itemHandler.Create)
		api.PUT("/vaults/:id/items/:itemId", itemHandler.Update)
		api.DELETE("/vaults/:id/items/:itemId", itemHandler.Delete)
		api.GET("/vaults/:id/items/:itemId/history", itemHandler.History)

		// Share links (management)
		api.POST("/vaults/:id/items/:itemId/share-link", shareLinkHandler.Create)
		api.GET("/vaults/:id/items/:itemId/share-links", shareLinkHandler.List)
		api.DELETE("/share-links/:id", shareLinkHandler.Delete)

		// Teams
		api.POST("/teams", teamHandler.Create)
		api.GET("/teams", teamHandler.List)
		api.GET("/teams/:teamId", teamHandler.Get)
		api.POST("/teams/:teamId/members", teamHandler.AddMember)
		api.DELETE("/teams/:teamId/members/:userId", teamHandler.RemoveMember)
		api.PUT("/teams/:teamId/members/:userId/role", teamHandler.UpdateMemberRole)
		api.GET("/teams/:teamId/members", teamHandler.ListMembers)
		api.GET("/teams/:teamId/pending-vault-keys", teamHandler.GetPendingVaultKeys)
		api.POST("/teams/:teamId/vaults", vaultHandler.CreateTeamVault)
		api.GET("/teams/:teamId/vaults", vaultHandler.ListByTeam)

		// Users
		api.POST("/users/keys", userHandler.UploadKeys)
		api.GET("/users/:userId/public-key", userHandler.GetPublicKey)
		api.PUT("/users/me", userHandler.UpdateMe)

		// Linked mobile devices (API tokens shown once, hash at rest)
		api.POST("/devices", deviceHandler.Create)
		api.GET("/devices", deviceHandler.List)
		api.DELETE("/devices/:id", deviceHandler.Revoke)

		// Admin-only global settings (auth middleware + admin email check)
		admin := api.Group("/admin")
		admin.Use(middleware.AdminOnly(userRepo, adminEmails))
		{
			admin.GET("/settings", settingsHandler.GetSettings)
			admin.PUT("/settings", settingsHandler.UpdateSettings)
		}
	}

	// Static files. The landing page lives at "/"; the app itself at "/app"
	// (and legacy "/index.html"). The landing's inline head script bounces
	// returning users (hash routes or mp-* localStorage) straight to /app,
	// and /landing keeps old links alive via a permanent redirect.
	r.StaticFile("/", "web/landing.html")
	r.StaticFile("/app", "web/index.html")
	// http.ServeFile would 301 any "/index.html" request to "/" (the landing),
	// so keep the legacy path pointing at the app with an explicit redirect.
	r.GET("/index.html", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/app")
	})
	r.GET("/landing", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/")
	})
	r.StaticFile("/styles.css", "web/styles.css")
	r.StaticFile("/app.js", "web/app.js")
	r.StaticFile("/crypto.js", "web/crypto.js")
	r.StaticFile("/srp.js", "web/srp.js")
	r.StaticFile("/blake2b.js", "web/blake2b.js")
	r.StaticFile("/generator.js", "web/generator.js")
	r.StaticFile("/strength.js", "web/strength.js")
	r.StaticFile("/breach.js", "web/breach.js")
	r.StaticFile("/import.js", "web/import.js")
	r.StaticFile("/i18n.js", "web/i18n.js")
	r.StaticFile("/icons.js", "web/icons.js")
	r.StaticFile("/attachments.js", "web/attachments.js")
	r.StaticFile("/sharelink.js", "web/sharelink.js")
	r.StaticFile("/duplicates.js", "web/duplicates.js")
	r.StaticFile("/onboarding.js", "web/onboarding.js")
	r.StaticFile("/qr.js", "web/qr.js")
	r.StaticFile("/keystore.js", "web/keystore.js")
	r.StaticFile("/export.js", "web/export.js")
	r.StaticFile("/kdbx-read.js", "web/kdbx-read.js")
	r.StaticFile("/sw.js", "web/sw.js")
	r.StaticFile("/manifest.json", "web/manifest.json")
	r.Static("/icons", "web/icons")

	// Fallback for SPA
	r.NoRoute(func(c *gin.Context) {
		c.File("web/index.html")
	})

	// Set correct MIME types
	jsPaths := map[string]bool{
		"/sw.js": true, "/app.js": true, "/crypto.js": true, "/srp.js": true,
		"/blake2b.js": true, "/generator.js": true, "/strength.js": true,
		"/breach.js": true, "/import.js": true, "/i18n.js": true,
		"/icons.js": true, "/attachments.js": true, "/sharelink.js": true,
		"/duplicates.js": true, "/onboarding.js": true, "/qr.js": true,
		"/keystore.js": true, "/export.js": true, "/kdbx-read.js": true,
	}
	r.Use(func(c *gin.Context) {
		if jsPaths[c.Request.URL.Path] {
			c.Header("Content-Type", "application/javascript")
		}
		if c.Request.URL.Path == "/manifest.json" {
			c.Header("Content-Type", "application/manifest+json")
		}
		c.Next()
	})

	// Service worker: no cache
	r.Use(func(c *gin.Context) {
		if c.Request.URL.Path == "/sw.js" {
			c.Header("Cache-Control", "no-cache")
			c.Header("Service-Worker-Allowed", "/")
		}
		c.Next()
	})

	return r
}
