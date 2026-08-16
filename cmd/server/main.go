package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/masorange/maspassword/internal/config"
	"github.com/masorange/maspassword/internal/database"
	"github.com/masorange/maspassword/internal/handler"
	"github.com/masorange/maspassword/internal/iap"
	"github.com/masorange/maspassword/internal/mailer"
	"github.com/masorange/maspassword/internal/oidc"
	"github.com/masorange/maspassword/internal/repository"
	"github.com/masorange/maspassword/internal/router"
	"github.com/masorange/maspassword/internal/service"
	"github.com/masorange/maspassword/internal/srp"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cfg := config.Load()

	// Retired deployment: with REDIRECT_ALL_TO set the server does nothing but
	// send every request to the new origin — no database, no app.
	if cfg.RedirectAllTo != "" {
		log.Printf("Redirect mode: every request -> %s (version=%s, port=%s)", cfg.RedirectAllTo, version, cfg.ServerPort)
		runServer(cfg.ServerPort, router.RedirectAll(cfg.RedirectAllTo))
		return
	}

	log.Printf("Starting server (version=%s, port=%s, iap=%v)", version, cfg.ServerPort, cfg.IAPEnabled)

	// Database
	log.Println("Connecting to database...")
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("Database connected")
	defer db.Close()

	if err := database.RunMigrations(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// SRP
	srpEnv, err := srp.NewEnvironment(cfg.SRPBits)
	if err != nil {
		log.Fatalf("Failed to initialize SRP: %v", err)
	}
	srpStore := srp.NewStore(5 * time.Minute)

	// IAP Validator (optional)
	var iapValidator *iap.Validator
	if cfg.IAPEnabled {
		if cfg.IAPAudience == "" {
			log.Fatalf("IAP_AUDIENCE is required when IAP_ENABLED=true")
		}
		iapValidator = iap.NewValidator(cfg.IAPAudience, cfg.IAPPublicKeyURL)
		log.Printf("IAP authentication enabled (audience: %s)", cfg.IAPAudience)
	}

	// SSO providers (optional, from OIDC_<ID>_* env vars)
	ssoRegistry := oidc.RegistryFromEnv()
	for _, p := range ssoRegistry.List() {
		log.Printf("SSO provider enabled: %s (%s)", p.ID, p.Name)
	}
	if !cfg.SignupEnabled {
		log.Println("Public signup disabled (SIGNUP_ENABLED=false)")
	}

	// Mailer (disabled no-op when MAILGUN_API_KEY/MAILGUN_DOMAIN are unset)
	mail := mailer.New(mailer.Config{
		APIKey:     cfg.MailgunAPIKey,
		Domain:     cfg.MailgunDomain,
		From:       cfg.MailgunFrom,
		EU:         cfg.MailgunEU,
		AppBaseURL: cfg.AppBaseURL,
	})
	if mail.Enabled() {
		log.Printf("Mailer enabled (domain: %s)", cfg.MailgunDomain)
	} else {
		log.Println("Mailer disabled (MAILGUN_API_KEY or MAILGUN_DOMAIN not set)")
	}

	// Repositories
	userRepo := repository.NewUserRepository(db)
	vaultRepo := repository.NewVaultRepository(db)
	itemRepo := repository.NewItemRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	vaultKeyRepo := repository.NewVaultKeyRepository(db)
	shareLinkRepo := repository.NewShareLinkRepository(db)
	settingsRepo := repository.NewSettingsRepository(db)
	deviceRepo := repository.NewDeviceTokenRepository(db)

	// Services
	authService := service.NewAuthService(userRepo, srpEnv, srpStore, cfg.JWTSecret)
	vaultService := service.NewVaultService(vaultRepo, vaultKeyRepo, teamRepo)
	itemService := service.NewItemService(itemRepo, vaultRepo, vaultKeyRepo)
	teamService := service.NewTeamService(teamRepo, userRepo, mail)
	shareLinkService := service.NewShareLinkService(shareLinkRepo, vaultRepo, itemRepo, teamRepo)

	// Handlers
	authHandler := handler.NewAuthHandler(authService)
	authHandler.SetAdminEmails(cfg.AdminEmails)
	// (signup toggle is wired by router.Setup from cfg.SignupEnabled)
	vaultHandler := handler.NewVaultHandler(vaultService)
	itemHandler := handler.NewItemHandler(itemService)
	teamHandler := handler.NewTeamHandler(teamService)
	userHandler := handler.NewUserHandler(userRepo)
	shareLinkHandler := handler.NewShareLinkHandler(shareLinkService)
	settingsHandler := handler.NewSettingsHandler(settingsRepo)
	deviceHandler := handler.NewDeviceHandler(deviceRepo)
	ssoHandler := handler.NewSSOHandler(ssoRegistry, cfg.JWTSecret, cfg.AppBaseURL, userRepo, mail)
	passkeyHandler := handler.NewPasskeyHandler(repository.NewPasskeyRepository(db), cfg.JWTSecret, cfg.AppBaseURL)

	if len(cfg.AdminEmails) > 0 {
		log.Printf("Admin panel enabled for %d email(s)", len(cfg.AdminEmails))
	}

	// Router
	r := router.Setup(
		authHandler, vaultHandler, itemHandler, teamHandler, userHandler, shareLinkHandler, settingsHandler,
		deviceHandler, ssoHandler, passkeyHandler, deviceRepo,
		cfg.JWTSecret, cfg.CORSOrigins,
		cfg.IAPEnabled, iapValidator, userRepo, cfg.AdminEmails,
		cfg.SignupEnabled,
		cfg.PasswordLoginEnabled,
		version,
	)

	runServer(cfg.ServerPort, r)
}

// runServer serves h on the given port until SIGINT/SIGTERM, then shuts down
// gracefully.
func runServer(port string, h http.Handler) {
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: h,
	}

	go func() {
		log.Printf("Server starting on port %s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Server exited")
}
