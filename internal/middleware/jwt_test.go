package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/iap"
	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/repository"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func makeToken(secret string, userID string, expiry time.Duration) string {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(expiry).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString([]byte(secret))
	return s
}

// --- Existing JWTAuth tests ---

func TestJWTAuth_ValidToken(t *testing.T) {
	secret := "test-secret"
	uid := uuid.New()
	token := makeToken(secret, uid.String(), time.Hour)

	r := gin.New()
	r.Use(JWTAuth(secret))
	r.GET("/test", func(c *gin.Context) {
		gotID := GetUserID(c)
		if gotID != uid {
			t.Errorf("expected user_id %s, got %s", uid, gotID)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestJWTAuth_MissingHeader(t *testing.T) {
	r := gin.New()
	r.Use(JWTAuth("secret"))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestJWTAuth_ExpiredToken(t *testing.T) {
	secret := "test-secret"
	token := makeToken(secret, uuid.New().String(), -time.Hour)

	r := gin.New()
	r.Use(JWTAuth(secret))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestJWTAuth_WrongSecret(t *testing.T) {
	token := makeToken("correct-secret", uuid.New().String(), time.Hour)

	r := gin.New()
	r.Use(JWTAuth("wrong-secret"))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- Mock UserRepository for DualAuth tests ---

type mockUserRepo struct {
	users map[string]*models.User
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{users: make(map[string]*models.User)}
}

func (m *mockUserRepo) Create(_ context.Context, user *models.User) error {
	user.ID = uuid.New()
	m.users[user.Email] = user
	return nil
}

func (m *mockUserRepo) GetByID(_ context.Context, id uuid.UUID) (*models.User, error) {
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, repository.ErrUserNotFound
}

func (m *mockUserRepo) GetByEmail(_ context.Context, email string) (*models.User, error) {
	if u, ok := m.users[email]; ok {
		return u, nil
	}
	return nil, repository.ErrUserNotFound
}

func (m *mockUserRepo) FindOrCreateByEmail(_ context.Context, email string) (*models.User, bool, error) {
	if u, ok := m.users[email]; ok {
		return u, false, nil
	}
	u := &models.User{ID: uuid.New(), Email: email}
	m.users[email] = u
	return u, true, nil
}

func (m *mockUserRepo) UpdateKeys(_ context.Context, _ uuid.UUID, _, _ string) error {
	return nil
}

func (m *mockUserRepo) UpdateSRPCredentials(_ context.Context, _ uuid.UUID, _, _ string) error {
	return nil
}

func (m *mockUserRepo) UpdateRecoveryKey(_ context.Context, _ uuid.UUID, _ string) error {
	return nil
}

func (m *mockUserRepo) UpdateFullCredentials(_ context.Context, _ uuid.UUID, _, _, _, _ string) error {
	return nil
}

func (m *mockUserRepo) UpdateDisplayName(_ context.Context, id uuid.UUID, name string) error {
	for _, u := range m.users {
		if u.ID == id {
			u.DisplayName = name
			return nil
		}
	}
	return repository.ErrUserNotFound
}

func (m *mockUserRepo) GetPublicKey(_ context.Context, _ uuid.UUID) (string, error) {
	return "", nil
}

func (m *mockUserRepo) GetPublicKeysByIDs(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]string, error) {
	return nil, nil
}

// --- IAP test helpers ---

func makeIAPTestKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key, "test-kid"
}

func serveTestJWKS(t *testing.T, key *ecdsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	x := base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes())

	type jwkKey struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Use string `json:"use"`
	}
	type jwkSet struct {
		Keys []jwkKey `json:"keys"`
	}

	jwks := jwkSet{Keys: []jwkKey{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: kid, Alg: "ES256", Use: "sig"}}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func makeIAPToken(t *testing.T, key *ecdsa.PrivateKey, kid, audience, email, sub string, exp time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":   "https://cloud.google.com/iap",
		"aud":   audience,
		"email": email,
		"sub":   sub,
		"iat":   time.Now().Unix(),
		"exp":   exp.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	signed, _ := token.SignedString(key)
	return signed
}

// --- DualAuth tests ---

func TestDualAuth_IAPHeader(t *testing.T) {
	key, kid := makeIAPTestKey(t)
	srv := serveTestJWKS(t, key, kid)

	audience := "/projects/123/apps/test"
	validator := iap.NewValidator(audience, srv.URL)
	repo := newMockUserRepo()

	r := gin.New()
	r.Use(DualAuth("jwt-secret", validator, repo))
	r.GET("/test", func(c *gin.Context) {
		method := GetAuthMethod(c)
		if method != "iap" {
			t.Errorf("expected auth_method 'iap', got '%s'", method)
		}
		uid := GetUserID(c)
		if uid == uuid.Nil {
			t.Error("expected non-nil user ID")
		}
		c.Status(http.StatusOK)
	})

	iapToken := makeIAPToken(t, key, kid, audience, "user@example.com", "sub1", time.Now().Add(time.Hour))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Goog-IAP-JWT-Assertion", iapToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestDualAuth_BearerFallback(t *testing.T) {
	key, kid := makeIAPTestKey(t)
	srv := serveTestJWKS(t, key, kid)

	audience := "/projects/123/apps/test"
	validator := iap.NewValidator(audience, srv.URL)
	repo := newMockUserRepo()

	secret := "test-secret"
	uid := uuid.New()
	bearerToken := makeToken(secret, uid.String(), time.Hour)

	r := gin.New()
	r.Use(DualAuth(secret, validator, repo))
	r.GET("/test", func(c *gin.Context) {
		method := GetAuthMethod(c)
		if method != "srp" {
			t.Errorf("expected auth_method 'srp', got '%s'", method)
		}
		gotID := GetUserID(c)
		if gotID != uid {
			t.Errorf("expected user_id %s, got %s", uid, gotID)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestDualAuth_IAPSetsDisplayName(t *testing.T) {
	key, kid := makeIAPTestKey(t)
	srv := serveTestJWKS(t, key, kid)

	audience := "/projects/123/apps/test"
	validator := iap.NewValidator(audience, srv.URL)
	repo := newMockUserRepo()

	r := gin.New()
	r.Use(DualAuth("jwt-secret", validator, repo))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	do := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Goog-IAP-JWT-Assertion", token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	// 1) No "name" claim → derived from the email local part.
	tok := makeIAPToken(t, key, kid, audience, "pablo.moncada@example.com", "sub1", time.Now().Add(time.Hour))
	if code := do(tok); code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if u := repo.users["pablo.moncada@example.com"]; u == nil || u.DisplayName != "Pablo Moncada" {
		t.Fatalf("expected derived display name 'Pablo Moncada', got %+v", u)
	}

	// 2) "name" claim present → used verbatim.
	claims := jwt.MapClaims{
		"iss":   "https://cloud.google.com/iap",
		"aud":   audience,
		"email": "ana@example.com",
		"sub":   "sub2",
		"name":  "Ana García",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	named := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	named.Header["kid"] = kid
	signed, err := named.SignedString(key)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	if code := do(signed); code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if u := repo.users["ana@example.com"]; u == nil || u.DisplayName != "Ana García" {
		t.Fatalf("expected display name from claim, got %+v", u)
	}

	// 3) An existing display name is never overwritten.
	repo.users["ana@example.com"].DisplayName = "Custom Name"
	if code := do(signed); code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if got := repo.users["ana@example.com"].DisplayName; got != "Custom Name" {
		t.Fatalf("display name must not be overwritten, got %q", got)
	}
}

func TestDualAuth_InvalidIAPToken(t *testing.T) {
	key, kid := makeIAPTestKey(t)
	srv := serveTestJWKS(t, key, kid)

	audience := "/projects/123/apps/test"
	validator := iap.NewValidator(audience, srv.URL)
	repo := newMockUserRepo()

	r := gin.New()
	r.Use(DualAuth("jwt-secret", validator, repo))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Goog-IAP-JWT-Assertion", "invalid-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestDualAuth_NoAuth(t *testing.T) {
	validator := iap.NewValidator("/test", "http://localhost:0")
	repo := newMockUserRepo()

	r := gin.New()
	r.Use(DualAuth("jwt-secret", validator, repo))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestDualAuth_IAPCreatesUser(t *testing.T) {
	key, kid := makeIAPTestKey(t)
	srv := serveTestJWKS(t, key, kid)

	audience := "/projects/123/apps/test"
	validator := iap.NewValidator(audience, srv.URL)
	repo := newMockUserRepo()

	r := gin.New()
	r.Use(DualAuth("jwt-secret", validator, repo))
	r.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	iapToken := makeIAPToken(t, key, kid, audience, "newuser@example.com", "sub1", time.Now().Add(time.Hour))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Goog-IAP-JWT-Assertion", iapToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Verify user was created
	if _, ok := repo.users["newuser@example.com"]; !ok {
		t.Error("expected user to be created in repo")
	}
}
