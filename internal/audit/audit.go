// Package audit emits structured audit events as single-line JSON on stdout.
//
// On Cloud Run any stdout line that parses as JSON becomes a Cloud Logging
// entry with its fields under jsonPayload, so the trail is queryable (and
// exportable to BigQuery) with zero extra infrastructure:
//
//	jsonPayload.audit=true AND jsonPayload.action="item.create"
//
// Two sources feed the stream:
//   - Middleware records every state-changing API call server-side. This is
//     the authoritative trail — a client cannot skip it.
//   - The client reports the actions the server cannot see under
//     zero-knowledge (revealing or copying a decrypted secret, exporting a
//     vault). Those arrive via POST /api/audit and are tagged source=client:
//     telemetry from an honest client, not evidence.
//
// Events carry only metadata (who, which vault/item id, when, from where) —
// never names, fields or values, which the server could not read anyway.
package audit

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/middleware"
)

var (
	mu  sync.Mutex
	out io.Writer = os.Stdout
	now           = time.Now
)

// SetOutput redirects the audit stream. Tests only.
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	out = w
}

// Emit writes one audit line. fields override the defaults (e.g. severity),
// and empty-string/nil values are dropped so lines stay compact.
func Emit(action, source string, fields map[string]any) {
	entry := map[string]any{
		"audit":    true,
		"time":     now().UTC().Format(time.RFC3339Nano),
		"severity": "INFO",
		"message":  "audit: " + action,
		"action":   action,
		"source":   source,
	}
	for k, v := range fields {
		if v == nil || v == "" {
			continue
		}
		entry[k] = v
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if out == nil { // nil output discards (tests)
		return
	}
	out.Write(append(line, '\n'))
}

// EmailResolver turns a user id into an email. Wired to the user repository
// by the router; kept as a func so the audit package needs no repository
// import.
type EmailResolver func(ctx context.Context, id uuid.UUID) (string, error)

// EmailCache memoizes resolutions so a log line never costs a DB round-trip
// after the first sighting of a user. Emails are immutable here; failures are
// retried after a short backoff so one DB hiccup doesn't blind the trail.
type EmailCache struct {
	resolve EmailResolver
	mu      sync.Mutex
	entries map[uuid.UUID]emailEntry
}

type emailEntry struct {
	email      string
	retryAfter time.Time // zero for successful lookups, which never expire
}

func NewEmailCache(resolve EmailResolver) *EmailCache {
	return &EmailCache{resolve: resolve, entries: make(map[uuid.UUID]emailEntry)}
}

// Email returns the user's email, or "" when it cannot be resolved (the event
// still carries user_id).
func (c *EmailCache) Email(ctx context.Context, id uuid.UUID) string {
	if c == nil || id == uuid.Nil {
		return ""
	}
	c.mu.Lock()
	entry, ok := c.entries[id]
	c.mu.Unlock()
	if ok && (entry.email != "" || now().Before(entry.retryAfter)) {
		return entry.email
	}
	email, err := c.resolve(ctx, id)
	entry = emailEntry{email: email}
	if err != nil {
		entry = emailEntry{retryAfter: now().Add(time.Minute)}
	}
	c.mu.Lock()
	c.entries[id] = entry
	c.mu.Unlock()
	return entry.email
}

// routeSpec names the audit action for one route and maps gin route params to
// audit field names.
type routeSpec struct {
	action string
	params map[string]string
}

// Every state-changing route, plus the sensitive reads worth a trail entry
// (item history exposes old passwords once decrypted client-side).
// POST /api/audit itself is absent on purpose: its handler emits directly.
var routes = map[string]routeSpec{
	"POST /auth/signup":                 {action: "auth.signup"},
	"POST /auth/login/step2":            {action: "auth.login"},
	"POST /auth/passkey/login":          {action: "auth.passkey_login"},
	"POST /auth/recover":                {action: "auth.recover"},
	"POST /auth/share-links/:id/redeem": {action: "share_link.redeem", params: map[string]string{"id": "share_link_id"}},

	"POST /api/auth/setup-encryption": {action: "auth.setup_encryption"},
	"POST /api/auth/passkeys":         {action: "passkey.register"},
	"DELETE /api/auth/passkeys/:id":   {action: "passkey.delete", params: map[string]string{"id": "passkey_id"}},

	"POST /api/vaults":           {action: "vault.create"},
	"DELETE /api/vaults/:id":     {action: "vault.delete", params: map[string]string{"id": "vault_id"}},
	"POST /api/vaults/:id/share": {action: "vault.share", params: map[string]string{"id": "vault_id"}},

	"POST /api/vaults/:id/items":                {action: "item.create", params: map[string]string{"id": "vault_id"}},
	"PUT /api/vaults/:id/items/:itemId":         {action: "item.update", params: map[string]string{"id": "vault_id", "itemId": "item_id"}},
	"DELETE /api/vaults/:id/items/:itemId":      {action: "item.delete", params: map[string]string{"id": "vault_id", "itemId": "item_id"}},
	"GET /api/vaults/:id/items/:itemId/history": {action: "item.history_viewed", params: map[string]string{"id": "vault_id", "itemId": "item_id"}},

	"POST /api/vaults/:id/items/:itemId/share-link": {action: "share_link.create", params: map[string]string{"id": "vault_id", "itemId": "item_id"}},
	"DELETE /api/share-links/:id":                   {action: "share_link.delete", params: map[string]string{"id": "share_link_id"}},

	"POST /api/teams":                             {action: "team.create"},
	"POST /api/teams/:teamId/members":             {action: "team.member_added", params: map[string]string{"teamId": "team_id"}},
	"DELETE /api/teams/:teamId/members/:userId":   {action: "team.member_removed", params: map[string]string{"teamId": "team_id", "userId": "target_user_id"}},
	"PUT /api/teams/:teamId/members/:userId/role": {action: "team.role_changed", params: map[string]string{"teamId": "team_id", "userId": "target_user_id"}},
	"POST /api/teams/:teamId/vaults":              {action: "vault.create_team", params: map[string]string{"teamId": "team_id"}},

	"POST /api/users/keys": {action: "user.keys_uploaded"},
	"PUT /api/users/me":    {action: "user.updated"},

	"POST /api/devices":       {action: "device.register"},
	"DELETE /api/devices/:id": {action: "device.revoke", params: map[string]string{"id": "device_id"}},
}

// Middleware records the routes above after they complete. Attach it to a
// group AFTER the auth middleware so the user id is already in the context;
// on the public auth group, handlers set the user id on success themselves.
// emails may be nil (events then carry only user_id).
func Middleware(emails *EmailCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		spec, ok := routes[c.Request.Method+" "+c.FullPath()]
		if !ok {
			return
		}
		status := c.Writer.Status()
		fields := map[string]any{
			"status":     status,
			"result":     "success",
			"ip":         c.ClientIP(),
			"user_agent": c.Request.UserAgent(),
		}
		if status >= 400 {
			fields["result"] = "failure"
			// Failed logins and signups are the security-relevant slice.
			if strings.HasPrefix(spec.action, "auth.") {
				fields["severity"] = "WARNING"
			}
		}
		if id := middleware.GetUserID(c); id != uuid.Nil {
			fields["user_id"] = id.String()
			fields["user_email"] = emails.Email(c.Request.Context(), id)
		}
		for param, field := range spec.params {
			if v := c.Param(param); v != "" {
				fields[field] = v
			}
		}
		Emit(spec.action, "server", fields)
	}
}
