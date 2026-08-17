package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/repository"
	"github.com/masorange/maspassword/pkg/dto"
)

var ErrNoVaultAccess = errors.New("no access to this vault")

type VaultService interface {
	Create(ctx context.Context, ownerID uuid.UUID, req dto.CreateVaultRequest) (*models.Vault, error)
	ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]models.Vault, error)
	ListAccessible(ctx context.Context, userID uuid.UUID) ([]models.Vault, error)
	CreateTeamVault(ctx context.Context, ownerID, teamID uuid.UUID, req dto.CreateTeamVaultRequest) (*models.Vault, error)
	GetVaultKey(ctx context.Context, userID, vaultID uuid.UUID) (*dto.VaultKeyResponse, error)
	ShareVault(ctx context.Context, userID, vaultID uuid.UUID, req dto.ShareVaultRequest) error
	ListByTeam(ctx context.Context, userID, teamID uuid.UUID) ([]models.Vault, error)
	ListShares(ctx context.Context, userID, vaultID uuid.UUID) ([]dto.VaultShareInfo, error)
	Delete(ctx context.Context, userID, vaultID uuid.UUID) error
}

type vaultService struct {
	vaultRepo    repository.VaultRepository
	vaultKeyRepo repository.VaultKeyRepository
	teamRepo     repository.TeamRepository
}

func NewVaultService(vaultRepo repository.VaultRepository, vaultKeyRepo repository.VaultKeyRepository, teamRepo repository.TeamRepository) VaultService {
	return &vaultService{vaultRepo: vaultRepo, vaultKeyRepo: vaultKeyRepo, teamRepo: teamRepo}
}

func (s *vaultService) Create(ctx context.Context, ownerID uuid.UUID, req dto.CreateVaultRequest) (*models.Vault, error) {
	vault := &models.Vault{
		OwnerID:       ownerID,
		NameEncrypted: req.NameEncrypted,
	}
	if err := s.vaultRepo.Create(ctx, vault); err != nil {
		return nil, fmt.Errorf("creating vault: %w", err)
	}
	return vault, nil
}

func (s *vaultService) ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]models.Vault, error) {
	vaults, err := s.vaultRepo.ListByOwner(ctx, ownerID)
	if err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}
	return vaults, nil
}

func (s *vaultService) ListAccessible(ctx context.Context, userID uuid.UUID) ([]models.Vault, error) {
	vaults, err := s.vaultRepo.ListAccessible(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing accessible vaults: %w", err)
	}
	return vaults, nil
}

func (s *vaultService) CreateTeamVault(ctx context.Context, ownerID, teamID uuid.UUID, req dto.CreateTeamVaultRequest) (*models.Vault, error) {
	// Verify user is a member of the team
	isMember, err := s.teamRepo.IsMember(ctx, teamID, ownerID)
	if err != nil {
		return nil, err
	}
	if !isMember {
		return nil, ErrNotTeamMember
	}

	vault := &models.Vault{
		OwnerID:       ownerID,
		NameEncrypted: req.NameEncrypted,
		TeamID:        &teamID,
	}
	if err := s.vaultRepo.Create(ctx, vault); err != nil {
		return nil, fmt.Errorf("creating team vault: %w", err)
	}

	// Record the vault↔team share for the owning team (idempotent).
	if err := s.vaultRepo.AddTeamShare(ctx, vault.ID, teamID); err != nil {
		return nil, fmt.Errorf("recording team share: %w", err)
	}

	// Create vault keys for each member
	for _, vke := range req.VaultKeys {
		uid, err := uuid.Parse(vke.UserID)
		if err != nil {
			return nil, fmt.Errorf("invalid user id in vault keys: %w", err)
		}
		vk := &models.VaultKey{
			VaultID:           vault.ID,
			UserID:            uid,
			EncryptedVaultKey: vke.EncryptedVaultKey,
		}
		if err := s.vaultKeyRepo.Create(ctx, vk); err != nil {
			return nil, fmt.Errorf("creating vault key: %w", err)
		}
	}

	return vault, nil
}

func (s *vaultService) GetVaultKey(ctx context.Context, userID, vaultID uuid.UUID) (*dto.VaultKeyResponse, error) {
	vk, err := s.vaultKeyRepo.GetByVaultAndUser(ctx, vaultID, userID)
	if err != nil {
		return nil, ErrNoVaultAccess
	}
	return &dto.VaultKeyResponse{
		EncryptedVaultKey: vk.EncryptedVaultKey,
	}, nil
}

func (s *vaultService) ShareVault(ctx context.Context, userID, vaultID uuid.UUID, req dto.ShareVaultRequest) error {
	// Verify user has access to vault (owner or has vault key)
	vault, err := s.vaultRepo.GetByID(ctx, vaultID)
	if err != nil {
		return err
	}
	if vault.OwnerID != userID {
		_, err := s.vaultKeyRepo.GetByVaultAndUser(ctx, vaultID, userID)
		if err != nil {
			return ErrNoVaultAccess
		}
	}

	// Create vault keys for new members
	for _, vke := range req.VaultKeys {
		uid, err := uuid.Parse(vke.UserID)
		if err != nil {
			return fmt.Errorf("invalid user id: %w", err)
		}
		vk := &models.VaultKey{
			VaultID:           vaultID,
			UserID:            uid,
			EncryptedVaultKey: vke.EncryptedVaultKey,
		}
		if err := s.vaultKeyRepo.Create(ctx, vk); err != nil {
			return fmt.Errorf("creating vault key: %w", err)
		}
	}

	// For team vaults, record the vault↔team share (idempotent).
	if vault.TeamID != nil {
		if err := s.vaultRepo.AddTeamShare(ctx, vaultID, *vault.TeamID); err != nil {
			return fmt.Errorf("recording team share: %w", err)
		}
	}
	return nil
}

func (s *vaultService) ListShares(ctx context.Context, userID, vaultID uuid.UUID) ([]dto.VaultShareInfo, error) {
	// Same access check as listing items: owner or holder of a vault key.
	vault, err := s.vaultRepo.GetByID(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	if vault.OwnerID != userID {
		if _, err := s.vaultKeyRepo.GetByVaultAndUser(ctx, vaultID, userID); err != nil {
			return nil, ErrNoVaultAccess
		}
	}

	shares, err := s.vaultRepo.ListTeamShares(ctx, vaultID)
	if err != nil {
		return nil, fmt.Errorf("listing vault shares: %w", err)
	}
	result := make([]dto.VaultShareInfo, 0, len(shares))
	for _, sh := range shares {
		result = append(result, dto.VaultShareInfo{
			TeamID:   sh.TeamID.String(),
			TeamName: sh.TeamName,
			SharedAt: sh.SharedAt,
		})
	}
	return result, nil
}

// Delete removes a vault and everything in it (items, history, keys, shares —
// the database cascades). Personal vaults can only be deleted by their owner;
// team vaults also by a team admin, so a team outlives the member who happened
// to create its vaults.
func (s *vaultService) Delete(ctx context.Context, userID, vaultID uuid.UUID) error {
	vault, err := s.vaultRepo.GetByID(ctx, vaultID)
	if err != nil {
		return err
	}
	if vault.OwnerID != userID {
		if vault.TeamID == nil {
			return ErrNoVaultAccess
		}
		member, err := s.teamRepo.GetMember(ctx, *vault.TeamID, userID)
		if err != nil || member.Role != "admin" {
			return ErrNoVaultAccess
		}
	}
	return s.vaultRepo.Delete(ctx, vaultID)
}

func (s *vaultService) ListByTeam(ctx context.Context, userID, teamID uuid.UUID) ([]models.Vault, error) {
	isMember, err := s.teamRepo.IsMember(ctx, teamID, userID)
	if err != nil {
		return nil, err
	}
	if !isMember {
		return nil, ErrNotTeamMember
	}
	return s.vaultRepo.ListByTeam(ctx, teamID)
}
