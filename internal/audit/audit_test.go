package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/middleware"
)

// capture redirects the audit stream to a buffer and returns a decoder over
// the lines written during fn.
func capture(t *testing.T, fn func()) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	SetOutput(&buf)
	t.Cleanup(func() { SetOutput(nil) })
	fn()
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("audit line is not valid JSON: %q: %v", line, err)
		}
		events = append(events, ev)
	}
	return events
}

func TestEmitShape(t *testing.T) {
	events := capture(t, func() {
		Emit("item.create", "server", map[string]any{
			"user_id":  "u1",
			"vault_id": "v1",
			"empty":    "", // dropped
			"severity": "WARNING",
		})
	})
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev["audit"] != true || ev["action"] != "item.create" || ev["source"] != "server" {
		t.Fatalf("bad envelope: %v", ev)
	}
	if ev["severity"] != "WARNING" {
		t.Fatalf("fields must override defaults, got severity %v", ev["severity"])
	}
	if ev["message"] != "audit: item.create" {
		t.Fatalf("bad message: %v", ev["message"])
	}
	if _, present := ev["empty"]; present {
		t.Fatal("empty values must be dropped")
	}
	if _, err := json.Marshal(ev["time"]); err != nil || ev["time"] == "" {
		t.Fatalf("missing time: %v", ev["time"])
	}
}

func testEngine(userID uuid.UUID, emails *EmailCache) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if userID != uuid.Nil {
			c.Set(middleware.UserIDKey, userID)
		}
	})
	r.Use(Middleware(emails))
	// Route patterns mirror the real router's audited ones.
	r.POST("/api/vaults/:id/items", func(c *gin.Context) { c.JSON(201, gin.H{}) })
	r.DELETE("/api/vaults/:id", func(c *gin.Context) { c.JSON(200, gin.H{}) })
	r.POST("/auth/login/step2", func(c *gin.Context) { c.JSON(401, gin.H{}) })
	r.GET("/api/vaults", func(c *gin.Context) { c.JSON(200, gin.H{}) })
	return r
}

func TestMiddlewareMapsRoutesAndParams(t *testing.T) {
	uid := uuid.New()
	vaultID := uuid.New().String()
	emails := NewEmailCache(func(_ context.Context, id uuid.UUID) (string, error) {
		if id == uid {
			return "ana@example.com", nil
		}
		return "", errors.New("unknown user")
	})
	events := capture(t, func() {
		r := testEngine(uid, emails)
		req := httptest.NewRequest(http.MethodPost, "/api/vaults/"+vaultID+"/items", nil)
		req.Header.Set("User-Agent", "test-agent")
		r.ServeHTTP(httptest.NewRecorder(), req)
	})
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev["action"] != "item.create" || ev["vault_id"] != vaultID {
		t.Fatalf("bad mapping: %v", ev)
	}
	if ev["user_id"] != uid.String() {
		t.Fatalf("user_id missing: %v", ev)
	}
	if ev["user_email"] != "ana@example.com" {
		t.Fatalf("user_email missing: %v", ev)
	}
	if ev["result"] != "success" || ev["status"] != float64(201) {
		t.Fatalf("bad result: %v", ev)
	}
	if ev["user_agent"] != "test-agent" {
		t.Fatalf("user_agent missing: %v", ev)
	}
}

func TestMiddlewareAuthFailureIsWarning(t *testing.T) {
	events := capture(t, func() {
		r := testEngine(uuid.Nil, nil)
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/auth/login/step2", nil))
	})
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev["action"] != "auth.login" || ev["result"] != "failure" || ev["severity"] != "WARNING" {
		t.Fatalf("failed login must be a WARNING failure: %v", ev)
	}
	if _, present := ev["user_id"]; present {
		t.Fatalf("failed login has no user: %v", ev)
	}
}

func TestMiddlewareIgnoresUnlistedRoutes(t *testing.T) {
	events := capture(t, func() {
		r := testEngine(uuid.New(), nil)
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/vaults", nil))
	})
	if len(events) != 0 {
		t.Fatalf("routine reads must not be audited, got %v", events)
	}
}

func TestEmailCache(t *testing.T) {
	uid := uuid.New()
	calls := 0
	failing := true
	cache := NewEmailCache(func(_ context.Context, id uuid.UUID) (string, error) {
		calls++
		if failing {
			return "", errors.New("db down")
		}
		return "ana@example.com", nil
	})

	// Failure: empty email, and the next call within the backoff window must
	// not hit the resolver again.
	if got := cache.Email(context.Background(), uid); got != "" {
		t.Fatalf("expected empty email on failure, got %q", got)
	}
	if got := cache.Email(context.Background(), uid); got != "" || calls != 1 {
		t.Fatalf("failure must be cached briefly: email %q, %d resolver calls", got, calls)
	}

	// After the backoff the resolver is retried and the success is memoized.
	failing = false
	oldNow := now
	now = func() time.Time { return oldNow().Add(2 * time.Minute) }
	defer func() { now = oldNow }()
	if got := cache.Email(context.Background(), uid); got != "ana@example.com" || calls != 2 {
		t.Fatalf("expected retry after backoff: email %q, %d calls", got, calls)
	}
	if got := cache.Email(context.Background(), uid); got != "ana@example.com" || calls != 2 {
		t.Fatalf("success must be cached forever: email %q, %d calls", got, calls)
	}

	// nil cache and nil uuid are safe no-ops.
	var nilCache *EmailCache
	if nilCache.Email(context.Background(), uid) != "" || cache.Email(context.Background(), uuid.Nil) != "" {
		t.Fatal("nil cache / nil id must resolve to empty")
	}
}

func TestSetOutputNilIsSafe(t *testing.T) {
	// capture's cleanup sets nil; emitting then must not panic.
	SetOutput(nil)
	defer SetOutput(nil)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Emit panicked with nil output: %v", r)
		}
	}()
	Emit("noop", "server", nil)
}
