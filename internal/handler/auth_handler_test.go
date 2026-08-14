package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

func (m *mockAuthService) GetSessionInfo(_ context.Context, _ uuid.UUID) (*dto.SessionInfoResponse, error) {
	return nil, nil
}

func (m *mockAuthService) SetupEncryption(_ context.Context, _ uuid.UUID, _ dto.SetupEncryptionRequest) error {
	return nil
}

func (m *mockAuthService) GetRecoveryData(_ context.Context, _ string) (*dto.RecoveryDataResponse, error) {
	return nil, nil
}

func (m *mockAuthService) GetRecoveryChallenge(_ context.Context, _ dto.RecoverChallengeRequest) (*dto.RecoverChallengeResponse, error) {
	return nil, nil
}

func (m *mockAuthService) Recover(_ context.Context, _ dto.RecoverRequest) error {
	return nil
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

func TestSignup_Disabled(t *testing.T) {
	h := NewAuthHandler(&mockAuthService{
		signupFn: func(ctx context.Context, req dto.SignupRequest) (*dto.SignupResponse, error) {
			t.Fatal("signup service must not be called when signup is disabled")
			return nil, nil
		},
	})
	h.SetSignupEnabled(false)
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

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["error"] != "signup disabled" {
		t.Errorf(`expected {"error":"signup disabled"}, got %s`, w.Body.String())
	}

	// Re-enabling restores the normal flow.
	h.SetSignupEnabled(true)
	h.authService = &mockAuthService{
		signupFn: func(ctx context.Context, req dto.SignupRequest) (*dto.SignupResponse, error) {
			return &dto.SignupResponse{ID: "id-1", Email: req.Email}, nil
		},
	}
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201 after re-enabling, got %d", w.Code)
	}
}
