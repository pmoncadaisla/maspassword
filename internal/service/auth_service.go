package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	gosrp "github.com/opencoff/go-srp"

	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/repository"
	"github.com/masorange/maspassword/internal/srp"
	"github.com/masorange/maspassword/pkg/dto"
)

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrSessionNotFound = errors.New("session not found or expired")

type AuthService interface {
	Signup(ctx context.Context, req dto.SignupRequest) (*dto.SignupResponse, error)
	LoginStep1(ctx context.Context, req dto.LoginStep1Request) (*dto.LoginStep1Response, error)
	LoginStep2(ctx context.Context, req dto.LoginStep2Request) (*dto.LoginStep2Response, error)
	GetSessionInfo(ctx context.Context, userID uuid.UUID) (*dto.SessionInfoResponse, error)
	SetupEncryption(ctx context.Context, userID uuid.UUID, req dto.SetupEncryptionRequest) error
	GetRecoveryData(ctx context.Context, email string) (*dto.RecoveryDataResponse, error)
	Recover(ctx context.Context, req dto.RecoverRequest) error
}

type authService struct {
	userRepo  repository.UserRepository
	srpEnv    *srp.Environment
	srpStore  *srp.Store
	jwtSecret []byte
}

func NewAuthService(
	userRepo repository.UserRepository,
	srpEnv *srp.Environment,
	srpStore *srp.Store,
	jwtSecret string,
) AuthService {
	return &authService{
		userRepo:  userRepo,
		srpEnv:    srpEnv,
		srpStore:  srpStore,
		jwtSecret: []byte(jwtSecret),
	}
}

func (s *authService) Signup(ctx context.Context, req dto.SignupRequest) (*dto.SignupResponse, error) {
	// Check for placeholder user (created via team invitation)
	existing, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err == nil && existing.SRPVerifier == nil {
		// Placeholder user — fill in credentials
		if err := s.userRepo.UpdateSRPCredentials(ctx, existing.ID, req.SRPSalt, req.SRPVerifier); err != nil {
			return nil, fmt.Errorf("updating placeholder credentials: %w", err)
		}
		if req.PublicKey != "" {
			if err := s.userRepo.UpdateKeys(ctx, existing.ID, req.PublicKey, req.EncryptedPrivateKey); err != nil {
				return nil, fmt.Errorf("updating placeholder keys: %w", err)
			}
		}
		if req.RecoveryEncryptedPrivateKey != "" {
			if err := s.userRepo.UpdateRecoveryKey(ctx, existing.ID, req.RecoveryEncryptedPrivateKey); err != nil {
				return nil, fmt.Errorf("updating placeholder recovery key: %w", err)
			}
		}
		return &dto.SignupResponse{ID: existing.ID.String(), Email: existing.Email}, nil
	}

	user := &models.User{
		Email:       req.Email,
		SRPSalt:     &req.SRPSalt,
		SRPVerifier: &req.SRPVerifier,
	}
	if req.PublicKey != "" {
		user.PublicKey = &req.PublicKey
	}
	if req.EncryptedPrivateKey != "" {
		user.EncryptedPrivateKey = &req.EncryptedPrivateKey
	}
	if req.RecoveryEncryptedPrivateKey != "" {
		user.RecoveryEncryptedPrivateKey = &req.RecoveryEncryptedPrivateKey
	}

	err = s.userRepo.Create(ctx, user)
	if err != nil {
		if errors.Is(err, repository.ErrEmailExists) {
			// Anti-enumeration: return generic error
			return nil, fmt.Errorf("signup failed")
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}

	return &dto.SignupResponse{
		ID:    user.ID.String(),
		Email: user.Email,
	}, nil
}

func (s *authService) LoginStep1(ctx context.Context, req dto.LoginStep1Request) (*dto.LoginStep1Response, error) {
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if errors.Is(err, repository.ErrUserNotFound) {
		// Anti-enumeration: return fake response
		return s.fakeLoginStep1Response(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("looking up user: %w", err)
	}

	// Check if user has SRP credentials (IAP-only users may not)
	if user.SRPVerifier == nil || user.SRPSalt == nil {
		return s.fakeLoginStep1Response(), nil
	}

	// Reconstruct verifier from stored data
	srpInstance, verifier, err := gosrp.MakeSRPVerifier(*user.SRPVerifier)
	if err != nil {
		return nil, fmt.Errorf("reconstructing verifier: %w", err)
	}

	// Parse client credentials to extract A
	clientCreds := req.ClientPublic
	_, clientA, err := gosrp.ServerBegin(clientCreds)
	if err != nil {
		return nil, fmt.Errorf("parsing client credentials: %w", err)
	}

	// Create server session
	server, err := srpInstance.NewServer(verifier, clientA)
	if err != nil {
		return nil, fmt.Errorf("creating SRP server: %w", err)
	}

	// Get server credentials (contains salt + B)
	serverCreds := server.Credentials()

	// Marshal server state for storage
	serverData := server.Marshal()

	// Generate session ID
	sessionID := uuid.New().String()

	// Store session
	s.srpStore.Set(sessionID, []byte(serverData), user.ID.String())

	return &dto.LoginStep1Response{
		SessionID:    sessionID,
		Salt:         *user.SRPSalt,
		ServerPublic: serverCreds,
	}, nil
}

func (s *authService) LoginStep2(ctx context.Context, req dto.LoginStep2Request) (*dto.LoginStep2Response, error) {
	serverData, userID, ok := s.srpStore.Get(req.SessionID)
	if !ok {
		return nil, ErrSessionNotFound
	}

	// Clean up session (one-time use)
	s.srpStore.Delete(req.SessionID)

	// Unmarshal server
	server, err := gosrp.UnmarshalServer(string(serverData))
	if err != nil {
		return nil, fmt.Errorf("unmarshaling server: %w", err)
	}

	// Verify client proof
	serverProof, ok := server.ClientOk(req.ClientProof)
	if !ok {
		return nil, ErrInvalidCredentials
	}

	// Generate JWT
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("parsing user id: %w", err)
	}

	token, err := s.generateJWT(uid)
	if err != nil {
		return nil, fmt.Errorf("generating token: %w", err)
	}

	resp := &dto.LoginStep2Response{
		Token:       token,
		ServerProof: serverProof,
	}

	// Fetch user to include encrypted_private_key
	user, err := s.userRepo.GetByID(ctx, uid)
	if err == nil && user.EncryptedPrivateKey != nil {
		resp.EncryptedPrivateKey = *user.EncryptedPrivateKey
	}

	return resp, nil
}

func (s *authService) GetSessionInfo(ctx context.Context, userID uuid.UUID) (*dto.SessionInfoResponse, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("getting user: %w", err)
	}

	token, err := s.generateJWT(userID)
	if err != nil {
		return nil, fmt.Errorf("generating token: %w", err)
	}

	resp := &dto.SessionInfoResponse{
		UserID:          userID.String(),
		Email:           user.Email,
		AuthMethod:      "iap",
		EncryptionSetup: user.EncryptedPrivateKey != nil && user.PublicKey != nil,
		Token:           token,
	}

	if user.EncryptedPrivateKey != nil {
		resp.EncryptedPrivateKey = *user.EncryptedPrivateKey
	}
	if user.SRPSalt != nil {
		resp.SRPSalt = *user.SRPSalt
	}

	return resp, nil
}

func (s *authService) SetupEncryption(ctx context.Context, userID uuid.UUID, req dto.SetupEncryptionRequest) error {
	// Check if encryption is already set up
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("getting user: %w", err)
	}
	if user.EncryptedPrivateKey != nil && user.PublicKey != nil {
		return fmt.Errorf("encryption already set up")
	}

	// Save SRP credentials
	if err := s.userRepo.UpdateSRPCredentials(ctx, userID, req.SRPSalt, req.SRPVerifier); err != nil {
		return fmt.Errorf("updating SRP credentials: %w", err)
	}

	// Save keys
	if err := s.userRepo.UpdateKeys(ctx, userID, req.PublicKey, req.EncryptedPrivateKey); err != nil {
		return fmt.Errorf("updating keys: %w", err)
	}

	// Save recovery key if provided
	if req.RecoveryEncryptedPrivateKey != "" {
		if err := s.userRepo.UpdateRecoveryKey(ctx, userID, req.RecoveryEncryptedPrivateKey); err != nil {
			return fmt.Errorf("updating recovery key: %w", err)
		}
	}

	return nil
}

func (s *authService) GetRecoveryData(ctx context.Context, email string) (*dto.RecoveryDataResponse, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		// Anti-enumeration: return generic error regardless of cause
		return nil, fmt.Errorf("recovery data not available")
	}

	if user.RecoveryEncryptedPrivateKey == nil || user.PublicKey == nil {
		return nil, fmt.Errorf("recovery data not available")
	}

	return &dto.RecoveryDataResponse{
		RecoveryEncryptedPrivateKey: *user.RecoveryEncryptedPrivateKey,
		PublicKey:                   *user.PublicKey,
	}, nil
}

func (s *authService) Recover(ctx context.Context, req dto.RecoverRequest) error {
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return fmt.Errorf("recovery failed")
	}

	if err := s.userRepo.UpdateFullCredentials(ctx, user.ID, req.SRPSalt, req.SRPVerifier, req.EncryptedPrivateKey, req.RecoveryEncryptedPrivateKey); err != nil {
		return fmt.Errorf("recovery failed")
	}

	return nil
}

func (s *authService) generateJWT(userID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID.String(),
		"exp":     time.Now().Add(1 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *authService) fakeLoginStep1Response() *dto.LoginStep1Response {
	fakeSalt := make([]byte, 16)
	rand.Read(fakeSalt)
	fakeB := make([]byte, 256)
	rand.Read(fakeB)
	return &dto.LoginStep1Response{
		SessionID:    uuid.New().String(),
		Salt:         hex.EncodeToString(fakeSalt),
		ServerPublic: hex.EncodeToString(fakeB),
	}
}
