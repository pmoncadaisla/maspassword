package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/masorange/maspassword/pkg/dto"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// mockAuthService implements service.AuthService for testing
type mockAuthService struct {
	signupFn     func(ctx context.Context, req dto.SignupRequest) (*dto.SignupResponse, error)
	loginStep1Fn func(ctx context.Context, req dto.LoginStep1Request) (*dto.LoginStep1Response, error)
	loginStep2Fn func(ctx context.Context, req dto.LoginStep2Request) (*dto.LoginStep2Response, error)
}

func (m *mockAuthService) Signup(ctx context.Context, req dto.SignupRequest) (*dto.SignupResponse, error) {
	return m.signupFn(ctx, req)
}

func (m *mockAuthService) LoginStep1(ctx context.Context, req dto.LoginStep1Request) (*dto.LoginStep1Response, error) {
	return m.loginStep1Fn(ctx, req)
}

func (m *mockAuthService) LoginStep2(ctx context.Context, req dto.LoginStep2Request) (*dto.LoginStep2Response, error) {
	return m.loginStep2Fn(ctx, req)
}

func TestSignup_Success(t *testing.T) {
	mock := &mockAuthService{
		signupFn: func(ctx context.Context, req dto.SignupRequest) (*dto.SignupResponse, error) {
			return &dto.SignupResponse{ID: "test-id", Email: req.Email}, nil
		},
	}

	h := NewAuthHandler(mock)
	r := gin.New()
	r.POST("/auth/signup", h.Signup)

	body, _ := json.Marshal(dto.SignupRequest{
		Email:       "test@example.com",
		SRPSalt:     "salt123",
		SRPVerifier: "verifier123",
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSignup_ValidationError(t *testing.T) {
	h := NewAuthHandler(&mockAuthService{})
	r := gin.New()
	r.POST("/auth/signup", h.Signup)

	body, _ := json.Marshal(map[string]string{"email": "invalid"})
	req := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
