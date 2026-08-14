package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	DatabaseURL     string
	JWTSecret       string
	ServerPort      string
	CORSOrigins     string
	SRPBits         int
	IAPEnabled      bool
	IAPAudience     string
	IAPPublicKeyURL string
	MailgunAPIKey   string
	MailgunDomain   string
	MailgunFrom     string
	MailgunEU       bool
	AppBaseURL      string
	AdminEmails     AdminEmails
}

// AdminEmails is a case-insensitive set of administrator email addresses.
// The zero value (nil) means "no admins".
type AdminEmails map[string]struct{}

// ParseAdminEmails builds an AdminEmails set from a comma-separated list.
// Entries are trimmed and lowercased; empty entries are ignored.
// An empty input yields an empty set (no admins).
func ParseAdminEmails(s string) AdminEmails {
	set := AdminEmails{}
	for _, part := range strings.Split(s, ",") {
		email := strings.ToLower(strings.TrimSpace(part))
		if email != "" {
			set[email] = struct{}{}
		}
	}
	return set
}

// Contains reports whether email belongs to the admin set (case-insensitive).
func (a AdminEmails) Contains(email string) bool {
	if len(a) == 0 {
		return false
	}
	_, ok := a[strings.ToLower(strings.TrimSpace(email))]
	return ok
}

func Load() *Config {
	srpBits := 2048
	if v := os.Getenv("SRP_BITS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			srpBits = n
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = os.Getenv("SERVER_PORT")
	}
	if port == "" {
		port = "8080"
	}

	iapEnabled := os.Getenv("IAP_ENABLED") == "true"

	iapPublicKeyURL := os.Getenv("IAP_PUBLIC_KEY_URL")
	if iapPublicKeyURL == "" {
		iapPublicKeyURL = "https://www.gstatic.com/iap/verify/public_key-jwk"
	}

	mailgunDomain := os.Getenv("MAILGUN_DOMAIN")
	mailgunFrom := os.Getenv("MAILGUN_FROM")
	if mailgunFrom == "" && mailgunDomain != "" {
		mailgunFrom = "MasPassword <noreply@" + mailgunDomain + ">"
	}

	return &Config{
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		JWTSecret:       os.Getenv("JWT_SECRET"),
		ServerPort:      port,
		CORSOrigins:     os.Getenv("CORS_ORIGINS"),
		SRPBits:         srpBits,
		IAPEnabled:      iapEnabled,
		IAPAudience:     os.Getenv("IAP_AUDIENCE"),
		IAPPublicKeyURL: iapPublicKeyURL,
		MailgunAPIKey:   os.Getenv("MAILGUN_API_KEY"),
		MailgunDomain:   mailgunDomain,
		MailgunFrom:     mailgunFrom,
		MailgunEU:       os.Getenv("MAILGUN_EU") == "true",
		AppBaseURL:      os.Getenv("APP_BASE_URL"),
		AdminEmails:     ParseAdminEmails(os.Getenv("ADMIN_EMAILS")),
	}
}
