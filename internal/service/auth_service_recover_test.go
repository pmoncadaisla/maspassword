package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/srp"
	"github.com/masorange/maspassword/pkg/dto"
)

// stubUserRepo is a minimal repository.UserRepository for testing Recover.
type stubUserRepo struct {
	updateFullCalledFor *uuid.UUID
}

func (s *stubUserRepo) Create(context.Context, *models.User) error { return nil }
func (s *stubUserRepo) GetByID(context.Context, uuid.UUID) (*models.User, error) {
	return nil, nil
}
func (s *stubUserRepo) GetByEmail(context.Context, string) (*models.User, error) {
	return nil, nil
}
func (s *stubUserRepo) FindOrCreateByEmail(context.Context, string) (*models.User, bool, error) {
	return nil, false, nil
}
func (s *stubUserRepo) UpdateKeys(context.Context, uuid.UUID, string, string) error { return nil }
func (s *stubUserRepo) UpdateSRPCredentials(context.Context, uuid.UUID, string, string) error {
	return nil
}
func (s *stubUserRepo) UpdateRecoveryKey(context.Context, uuid.UUID, string) error { return nil }
func (s *stubUserRepo) UpdateFullCredentials(_ context.Context, id uuid.UUID, _, _, _, _ string) error {
	s.updateFullCalledFor = &id
	return nil
}
func (s *stubUserRepo) UpdateDisplayName(context.Context, uuid.UUID, string) error { return nil }
func (s *stubUserRepo) GetPublicKey(context.Context, uuid.UUID) (string, error)    { return "", nil }
func (s *stubUserRepo) GetPublicKeysByIDs(context.Context, []uuid.UUID) (map[uuid.UUID]string, error) {
	return nil, nil
}

func TestRecover_RejectsUnknownChallenge(t *testing.T) {
	repo := &stubUserRepo{}
	s := &authService{userRepo: repo, recoveryStore: srp.NewStore(time.Minute)}

	err := s.Recover(context.Background(), dto.RecoverRequest{
		ChallengeID: "does-not-exist", Nonce: "whatever",
		SRPSalt: "s", SRPVerifier: "v", EncryptedPrivateKey: "e", RecoveryEncryptedPrivateKey: "r",
	})
	if err == nil {
		t.Fatal("expected error for unknown challenge, got nil")
	}
	if repo.updateFullCalledFor != nil {
		t.Fatal("credentials must NOT be updated without a valid challenge")
	}
}

func TestRecover_RejectsWrongNonceAndIsOneTime(t *testing.T) {
	repo := &stubUserRepo{}
	store := srp.NewStore(time.Minute)
	s := &authService{userRepo: repo, recoveryStore: store}

	uid := uuid.New()
	store.Set("cid", []byte("the-real-nonce"), uid.String())

	// Wrong nonce is rejected...
	if err := s.Recover(context.Background(), dto.RecoverRequest{
		ChallengeID: "cid", Nonce: "wrong-nonce",
		SRPSalt: "s", SRPVerifier: "v", EncryptedPrivateKey: "e", RecoveryEncryptedPrivateKey: "r",
	}); err == nil {
		t.Fatal("expected error for wrong nonce, got nil")
	}
	if repo.updateFullCalledFor != nil {
		t.Fatal("credentials must NOT be updated with a wrong nonce")
	}

	// ...and the challenge is consumed (one-time use), so even the correct nonce now fails.
	if err := s.Recover(context.Background(), dto.RecoverRequest{
		ChallengeID: "cid", Nonce: "the-real-nonce",
		SRPSalt: "s", SRPVerifier: "v", EncryptedPrivateKey: "e", RecoveryEncryptedPrivateKey: "r",
	}); err == nil {
		t.Fatal("challenge should be single-use; second attempt must fail")
	}
}

func TestRecover_SucceedsWithValidChallenge(t *testing.T) {
	repo := &stubUserRepo{}
	store := srp.NewStore(time.Minute)
	s := &authService{userRepo: repo, recoveryStore: store}

	uid := uuid.New()
	store.Set("cid", []byte("the-real-nonce"), uid.String())

	err := s.Recover(context.Background(), dto.RecoverRequest{
		ChallengeID: "cid", Nonce: "the-real-nonce",
		SRPSalt: "s", SRPVerifier: "v", EncryptedPrivateKey: "e", RecoveryEncryptedPrivateKey: "r",
	})
	if err != nil {
		t.Fatalf("expected success with valid challenge, got %v", err)
	}
	if repo.updateFullCalledFor == nil || *repo.updateFullCalledFor != uid {
		t.Fatal("credentials must be updated for the challenged user id")
	}
}

func TestParseRSAPublicKeyJWK_RoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pub := &key.PublicKey

	// Build a JWK the way the Web Crypto API exports it.
	var eBytes []byte
	for e := pub.E; e > 0; e >>= 8 {
		eBytes = append([]byte{byte(e & 0xff)}, eBytes...)
	}
	jwk, _ := json.Marshal(map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	})

	parsed, err := parseRSAPublicKeyJWK(string(jwk))
	if err != nil {
		t.Fatalf("parsing JWK: %v", err)
	}
	if parsed.E != pub.E || parsed.N.Cmp(pub.N) != 0 {
		t.Fatalf("parsed key mismatch: got E=%d N=%s", parsed.E, parsed.N)
	}
}
