package config

import (
	"os"
	"strconv"
)

type Config struct {
	DatabaseURL string
	JWTSecret   string
	ServerPort  string
	CORSOrigins string
	SRPBits    int
}

func Load() *Config {
	srpBits := 2048
	if v := os.Getenv("SRP_BITS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			srpBits = n
		}
	}

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	return &Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		ServerPort:  port,
		CORSOrigins: os.Getenv("CORS_ORIGINS"),
		SRPBits:     srpBits,
	}
}
