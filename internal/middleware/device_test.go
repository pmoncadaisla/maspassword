package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/devicetoken"
	"github.com/masorange/maspassword/internal/iap"
	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/repository"
)

// --- Fake DeviceTokenRepository ---

type fakeDeviceRepo struct {
	rows    map[uuid.UUID]*models.DeviceToken
	getErr  error
	touched []uuid.UUID
}

func newFakeDeviceRepo() *fakeDeviceRepo {
	return &fakeDeviceRepo{rows: map[uuid.UUID]*models.DeviceToken{}}
}

func (f *fakeDeviceRepo) Create(_ context.Context, t *models.DeviceToken) error {
	t.CreatedAt = time.Now()
	f.rows[t.ID] = t
	return nil
}

func (f *fakeDeviceRepo) GetByID(_ context.Context, id uuid.UUID) (*models.DeviceToken, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if t, ok := f.rows[id]; ok {
		copied := *t
		return &copied, nil
	}
	return nil, repository.ErrDeviceTokenNotFound
}

func (f *fakeDeviceRepo) ListByUser(_ context.Context, userID uuid.UUID) ([]models.DeviceToken, error) {
	out := []models.DeviceToken{}
	for _, t := range f.rows {
		if t.UserID == userID {
			out = append(out, *t)
		}
	}
	return out, nil
}

func (f *fakeDeviceRepo) Revoke(_ context.Context, id, userID uuid.UUID) error {
	t, ok := f.rows[id]
	if !ok || t.UserID != userID {
		return repository.ErrDeviceTokenNotFound
	}
	if t.RevokedAt == nil {
		now := time.Now()
		t.RevokedAt = &now
	}
	return nil
}

func (f *fakeDeviceRepo) TouchLastUsed(_ context.Context, id uuid.UUID) error {
	f.touched = append(f.touched, id)
	if t, ok := f.rows[id]; ok {
		now := time.Now()
		t.LastUsedAt = &now
	}
	return nil
}

// seedDevice creates a valid device token owned by userID and returns the
// plaintext token.
func seedDevice(t *testing.T, repo *fakeDeviceRepo, userID uuid.UUID) (string, uuid.UUID) {
	t.Helper()
	id, token, hash, err := devicetoken.Generate()
	if err != nil {
		t.Fatalf("generating device token: %v", err)
	}
	repo.rows[id] = &models.DeviceToken{ID: id, UserID: userID, Name: "test phone", TokenHash: hash, CreatedAt: time.Now()}
	return token, id
}

func deviceTestRouter(repo *fakeDeviceRepo, jwtSecret string, capture *uuid.UUID) *gin.Engine {
	r := gin.New()
	r.Use(DeviceTokenAuth(repo, JWTAuth(jwtSecret)))
	r.GET("/test", func(c *gin.Context) {
		if capture != nil {
			*capture = GetUserID(c)
		}
		c.Status(http.StatusOK)
	})
	return r
}

func doDeviceReq(r *gin.Engine, authHeader string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// --- Tests ---

func TestDeviceTokenAuth_ValidToken(t *testing.T) {
	repo := newFakeDeviceRepo()
	userID := uuid.New()
	token, id := seedDevice(t, repo, userID)

	var got uuid.UUID
	r := deviceTestRouter(repo, "secret", &got)

	w := doDeviceReq(r, "Bearer "+token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if got != userID {
		t.Errorf("expected user_id %s in context, got %s", userID, got)
	}
	// First use: last_used_at was NULL → touched.
	if len(repo.touched) != 1 || repo.touched[0] != id {
		t.Errorf("expected one TouchLastUsed(%s), got %v", id, repo.touched)
	}
}

func TestDeviceTokenAuth_SetsDeviceAuthMethod(t *testing.T) {
	repo := newFakeDeviceRepo()
	token, _ := seedDevice(t, repo, uuid.New())

	r := gin.New()
	r.Use(DeviceTokenAuth(repo, JWTAuth("secret")))
	r.GET("/test", func(c *gin.Context) {
		if m := GetAuthMethod(c); m != "device" {
			t.Errorf("expected auth_method 'device', got %q", m)
		}
		c.Status(http.StatusOK)
	})

	if w := doDeviceReq(r, "Bearer "+token); w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestDeviceTokenAuth_Revoked(t *testing.T) {
	repo := newFakeDeviceRepo()
	userID := uuid.New()
	token, id := seedDevice(t, repo, userID)
	now := time.Now()
	repo.rows[id].RevokedAt = &now

	r := deviceTestRouter(repo, "secret", nil)
	w := doDeviceReq(r, "Bearer "+token)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked token, got %d", w.Code)
	}
	if len(repo.touched) != 0 {
		t.Errorf("revoked token must not refresh last_used_at, got %v", repo.touched)
	}
}

func TestDeviceTokenAuth_GarbageTokens(t *testing.T) {
	repo := newFakeDeviceRepo()
	userID := uuid.New()
	token, id := seedDevice(t, repo, userID)

	cases := map[string]string{
		"malformed (no uuid)": "Bearer mpd_garbage",
		"unknown id":          "Bearer mpd_" + uuid.New().String() + "_c2VjcmV0c2VjcmV0",
		"wrong secret":        "Bearer mpd_" + id.String() + "_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"truncated secret":    "Bearer " + token[:len(token)-5],
		"empty secret":        "Bearer mpd_" + id.String() + "_",
		"prefix only":         "Bearer mpd_",
		"underscored secret":  "Bearer mpd_" + id.String() + "_x_y-z_0123456789abcdefghijklmnopqrstuvwxyzA",
	}
	r := deviceTestRouter(repo, "secret", nil)
	for name, header := range cases {
		if w := doDeviceReq(r, header); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401, got %d", name, w.Code)
		}
	}
}

func TestDeviceTokenAuth_RepoErrorIs500(t *testing.T) {
	repo := newFakeDeviceRepo()
	token, _ := seedDevice(t, repo, uuid.New())
	repo.getErr = errors.New("db down")

	r := deviceTestRouter(repo, "secret", nil)
	if w := doDeviceReq(r, "Bearer "+token); w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on repo error, got %d", w.Code)
	}
}

func TestDeviceTokenAuth_FallsBackToJWT(t *testing.T) {
	repo := newFakeDeviceRepo()
	secret := "test-secret"
	uid := uuid.New()
	jwtToken := makeToken(secret, uid.String(), time.Hour)

	var got uuid.UUID
	r := deviceTestRouter(repo, secret, &got)

	// Regular JWT bearer goes through the fallback untouched.
	if w := doDeviceReq(r, "Bearer "+jwtToken); w.Code != http.StatusOK {
		t.Fatalf("expected 200 via JWT fallback, got %d", w.Code)
	}
	if got != uid {
		t.Errorf("expected user_id %s via JWT fallback, got %s", uid, got)
	}

	// Missing auth is rejected by the fallback.
	if w := doDeviceReq(r, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

func TestDeviceTokenAuth_WorksUnderDualAuth(t *testing.T) {
	repo := newFakeDeviceRepo()
	userID := uuid.New()
	token, _ := seedDevice(t, repo, userID)

	// Real IAP validator wired to a local JWKS server, exactly like the
	// DualAuth tests — proves the device path takes priority in IAP mode.
	key, kid := makeIAPTestKey(t)
	srv := serveTestJWKS(t, key, kid)
	validator := iap.NewValidator("/projects/123/apps/test", srv.URL)
	userRepo := newMockUserRepo()

	var got uuid.UUID
	r := gin.New()
	r.Use(DeviceTokenAuth(repo, DualAuth("jwt-secret", validator, userRepo)))
	r.GET("/test", func(c *gin.Context) {
		got = GetUserID(c)
		c.Status(http.StatusOK)
	})

	w := doDeviceReq(r, "Bearer "+token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 under DualAuth, got %d", w.Code)
	}
	if got != userID {
		t.Errorf("expected user_id %s, got %s", userID, got)
	}
}

func TestDeviceTokenAuth_LastUsedThrottle(t *testing.T) {
	repo := newFakeDeviceRepo()
	userID := uuid.New()
	token, id := seedDevice(t, repo, userID)

	r := deviceTestRouter(repo, "secret", nil)

	// last_used_at 30s ago → within the 60s window → NOT touched.
	recent := time.Now().Add(-30 * time.Second)
	repo.rows[id].LastUsedAt = &recent
	if w := doDeviceReq(r, "Bearer "+token); w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(repo.touched) != 0 {
		t.Errorf("expected no touch within 60s, got %v", repo.touched)
	}

	// last_used_at 2min ago → stale → touched.
	old := time.Now().Add(-2 * time.Minute)
	repo.rows[id].LastUsedAt = &old
	if w := doDeviceReq(r, "Bearer "+token); w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(repo.touched) != 1 {
		t.Errorf("expected exactly one touch for stale last_used_at, got %v", repo.touched)
	}
}
