package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/config"
	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/repository"
)

// stubUserRepo implements only GetByID; the embedded interface panics on any
// other method (which AdminOnly must never call).
type stubUserRepo struct {
	repository.UserRepository
	users map[uuid.UUID]*models.User
}

func (s *stubUserRepo) GetByID(_ context.Context, id uuid.UUID) (*models.User, error) {
	if u, ok := s.users[id]; ok {
		return u, nil
	}
	return nil, repository.ErrUserNotFound
}

func adminTestRouter(userRepo repository.UserRepository, admins config.AdminEmails, userID uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// Simulate the auth middleware having resolved the session user.
	r.Use(func(c *gin.Context) {
		if userID != uuid.Nil {
			c.Set(UserIDKey, userID)
		}
		c.Next()
	})
	r.Use(AdminOnly(userRepo, admins))
	r.GET("/api/admin/settings", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func doAdminReq(t *testing.T, r *gin.Engine) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/settings", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAdminOnly_AllowsAdminEmailCaseInsensitive(t *testing.T) {
	id := uuid.New()
	repo := &stubUserRepo{users: map[uuid.UUID]*models.User{
		id: {ID: id, Email: "Admin@Example.COM"},
	}}
	admins := config.ParseAdminEmails("admin@example.com")

	w := doAdminReq(t, adminTestRouter(repo, admins, id))
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for admin, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminOnly_RejectsNonAdmin(t *testing.T) {
	id := uuid.New()
	repo := &stubUserRepo{users: map[uuid.UUID]*models.User{
		id: {ID: id, Email: "user@example.com"},
	}}
	admins := config.ParseAdminEmails("admin@example.com")

	w := doAdminReq(t, adminTestRouter(repo, admins, id))
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestAdminOnly_EmptyAdminListRejectsEveryone(t *testing.T) {
	id := uuid.New()
	repo := &stubUserRepo{users: map[uuid.UUID]*models.User{
		id: {ID: id, Email: "admin@example.com"},
	}}

	w := doAdminReq(t, adminTestRouter(repo, config.ParseAdminEmails(""), id))
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 with empty admin list, got %d", w.Code)
	}
}

func TestAdminOnly_UnknownUserRejected(t *testing.T) {
	repo := &stubUserRepo{users: map[uuid.UUID]*models.User{}}
	admins := config.ParseAdminEmails("admin@example.com")

	// user_id set but not found in the repo
	w := doAdminReq(t, adminTestRouter(repo, admins, uuid.New()))
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unknown user, got %d", w.Code)
	}

	// no user_id in context at all
	w = doAdminReq(t, adminTestRouter(repo, admins, uuid.Nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 without session user, got %d", w.Code)
	}
}
