package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
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
	jwtSecret string,
	corsOrigins string,
	iapEnabled bool,
	iapValidator *iap.Validator,
	userRepo repository.UserRepository,
) *gin.Engine {
	r := gin.New()

	r.Use(middleware.ErrorHandler())
	r.Use(middleware.Logger())
	r.Use(middleware.CORS(corsOrigins))

	// Public routes (no JWT)
	auth := r.Group("/auth")
	{
		auth.POST("/signup", authHandler.Signup)
		auth.POST("/login/step1", authHandler.LoginStep1)
		auth.POST("/login/step2", authHandler.LoginStep2)
		auth.GET("/mode", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"iap_enabled": iapEnabled})
		})
	}

	// Choose auth middleware based on IAP config
	var authMiddleware gin.HandlerFunc
	if iapValidator != nil {
		authMiddleware = middleware.DualAuth(jwtSecret, iapValidator, userRepo)
	} else {
		authMiddleware = middleware.JWTAuth(jwtSecret)
	}

	// Protected routes
	api := r.Group("/api")
	api.Use(authMiddleware)
	{
		// Auth session (for IAP flow)
		api.GET("/auth/session", authHandler.GetSession)
		api.POST("/auth/setup-encryption", authHandler.SetupEncryption)

		// Vaults
		api.GET("/vaults", vaultHandler.List)
		api.POST("/vaults", vaultHandler.Create)
		api.GET("/vaults/:id/key", vaultHandler.GetVaultKey)
		api.POST("/vaults/:id/share", vaultHandler.ShareVault)

		// Items
		api.GET("/vaults/:id/items", itemHandler.List)
		api.POST("/vaults/:id/items", itemHandler.Create)
		api.PUT("/vaults/:id/items/:itemId", itemHandler.Update)

		// Teams
		api.POST("/teams", teamHandler.Create)
		api.GET("/teams", teamHandler.List)
		api.GET("/teams/:teamId", teamHandler.Get)
		api.POST("/teams/:teamId/members", teamHandler.AddMember)
		api.DELETE("/teams/:teamId/members/:userId", teamHandler.RemoveMember)
		api.GET("/teams/:teamId/members", teamHandler.ListMembers)
		api.POST("/teams/:teamId/vaults", vaultHandler.CreateTeamVault)
		api.GET("/teams/:teamId/vaults", vaultHandler.ListByTeam)

		// Users
		api.POST("/users/keys", userHandler.UploadKeys)
		api.GET("/users/:userId/public-key", userHandler.GetPublicKey)
	}

	// Static files (PWA frontend)
	r.StaticFile("/", "web/index.html")
	r.StaticFile("/index.html", "web/index.html")
	r.StaticFile("/styles.css", "web/styles.css")
	r.StaticFile("/app.js", "web/app.js")
	r.StaticFile("/crypto.js", "web/crypto.js")
	r.StaticFile("/srp.js", "web/srp.js")
	r.StaticFile("/blake2b.js", "web/blake2b.js")
	r.StaticFile("/sw.js", "web/sw.js")
	r.StaticFile("/manifest.json", "web/manifest.json")
	r.Static("/icons", "web/icons")

	// Fallback for SPA
	r.NoRoute(func(c *gin.Context) {
		c.File("web/index.html")
	})

	// Set correct MIME types
	r.Use(func(c *gin.Context) {
		if c.Request.URL.Path == "/sw.js" || c.Request.URL.Path == "/app.js" ||
			c.Request.URL.Path == "/crypto.js" || c.Request.URL.Path == "/srp.js" ||
			c.Request.URL.Path == "/blake2b.js" {
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
