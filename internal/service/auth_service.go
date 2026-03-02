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
	user := &models.User{
		Email:       req.Email,
		SRPSalt:     req.SRPSalt,
		SRPVerifier: req.SRPVerifier,
	}
	if req.PublicKey != "" {
		user.PublicKey = &req.PublicKey
	}
	if req.EncryptedPrivateKey != "" {
		user.EncryptedPrivateKey = &req.EncryptedPrivateKey
	}

	err := s.userRepo.Create(ctx, user)
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

	// Reconstruct verifier from stored data
	srpInstance, verifier, err := gosrp.MakeSRPVerifier(user.SRPVerifier)
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
		Salt:         user.SRPSalt,
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
