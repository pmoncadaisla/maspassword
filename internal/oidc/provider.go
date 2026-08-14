// Package oidc implements app-level single sign-on via OpenID Connect.
//
// The design is provider-agnostic: every IdP (Google today, Okta or Azure
// Entra tomorrow) is described by the same Provider struct, configured purely
// from OIDC_<ID>_* environment variables and registered in RegistryFromEnv.
// The authorization-code + PKCE flow, discovery, JWKS caching and ID-token
// validation are shared by all providers; nothing outside this package is
// Google-specific.
package oidc

import (
	"os"
	"strings"
)

// Provider is the static configuration of one OIDC identity provider.
type Provider struct {
	ID           string // URL-safe identifier ("google", "okta", ...)
	DisplayName  string // human name for login buttons ("Google")
	Issuer       string // expected `iss` claim; also the discovery base URL
	ClientID     string
	ClientSecret string

	// Optional endpoint overrides. When all three are set, the
	// .well-known/openid-configuration discovery is skipped entirely, so
	// non-discovery IdPs (or Google's IAM-OAuth variant) can be wired by
	// env alone.
	AuthURLOverride  string
	TokenURLOverride string
	JWKSURLOverride  string

	// AllowedDomains restricts sign-in to emails (or Google `hd` claims)
	// in these domains. Empty means any domain.
	AllowedDomains []string
}

// ProviderInfo is the public shape exposed to the frontend
// (GET /auth/sso/providers and the sso_providers field of /auth/mode).
type ProviderInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Registry holds the configured providers and their runtime clients
// (cached discovery documents and JWKS keys).
type Registry struct {
	order   []string
	clients map[string]*Client
}

// NewRegistry builds a registry from static provider configs.
func NewRegistry(providers []Provider) *Registry {
	r := &Registry{clients: make(map[string]*Client)}
	for _, p := range providers {
		if _, dup := r.clients[p.ID]; dup {
			continue
		}
		r.order = append(r.order, p.ID)
		r.clients[p.ID] = newClient(p)
	}
	return r
}

// Get returns the runtime client for a provider id.
func (r *Registry) Get(id string) (*Client, bool) {
	c, ok := r.clients[id]
	return c, ok
}

// List returns the providers in registration order. Never nil, so it
// serializes as [] in JSON when no provider is configured.
func (r *Registry) List() []ProviderInfo {
	out := make([]ProviderInfo, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, ProviderInfo{ID: id, Name: r.clients[id].DisplayName})
	}
	return out
}

// Empty reports whether no provider is configured.
func (r *Registry) Empty() bool { return len(r.order) == 0 }

// knownProviders is the extension point: enabling SSO for a new IdP is one
// line here plus its OIDC_<ID>_* env vars. IdPs without a well-known default
// issuer (Okta orgs, Entra tenants) require OIDC_<ID>_ISSUER to be set.
var knownProviders = []struct{ id, name, defaultIssuer string }{
	{"google", "Google", "https://accounts.google.com"},
	// {"okta", "Okta", ""},                 // OIDC_OKTA_ISSUER=https://<org>.okta.com
	// {"entra", "Microsoft Entra ID", ""},  // OIDC_ENTRA_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0
}

// RegistryFromEnv builds the registry from environment variables. A provider
// is registered iff OIDC_<ID>_CLIENT_ID and OIDC_<ID>_CLIENT_SECRET are set.
// OIDC_ALLOWED_DOMAINS (comma-separated) applies to all providers.
func RegistryFromEnv() *Registry {
	domains := splitDomains(os.Getenv("OIDC_ALLOWED_DOMAINS"))
	var ps []Provider
	for _, k := range knownProviders {
		if p, ok := providerFromEnv(k.id, k.name, k.defaultIssuer, domains); ok {
			ps = append(ps, p)
		}
	}
	return NewRegistry(ps)
}

// providerFromEnv reads OIDC_<ID>_CLIENT_ID/CLIENT_SECRET/ISSUER and the
// optional AUTH_URL/TOKEN_URL/JWKS_URL endpoint overrides.
func providerFromEnv(id, name, defaultIssuer string, domains []string) (Provider, bool) {
	prefix := "OIDC_" + strings.ToUpper(id) + "_"
	clientID := os.Getenv(prefix + "CLIENT_ID")
	clientSecret := os.Getenv(prefix + "CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		return Provider{}, false
	}
	issuer := strings.TrimSuffix(os.Getenv(prefix+"ISSUER"), "/")
	if issuer == "" {
		issuer = defaultIssuer
	}
	if issuer == "" {
		return Provider{}, false
	}
	return Provider{
		ID:               id,
		DisplayName:      name,
		Issuer:           issuer,
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		AuthURLOverride:  os.Getenv(prefix + "AUTH_URL"),
		TokenURLOverride: os.Getenv(prefix + "TOKEN_URL"),
		JWKSURLOverride:  os.Getenv(prefix + "JWKS_URL"),
		AllowedDomains:   domains,
	}, true
}

// splitDomains parses a comma-separated domain list, lowercased and with any
// leading "@" stripped. Empty entries are ignored.
func splitDomains(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if d := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(part)), "@"); d != "" {
			out = append(out, d)
		}
	}
	return out
}
