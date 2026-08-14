package config

import (
	"os"
	"strconv"
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
	}
}
