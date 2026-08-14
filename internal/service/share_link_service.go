package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/repository"
	"github.com/masorange/maspassword/pkg/dto"
)

var ErrShareLinkForbidden = errors.New("not allowed to manage share links for this vault")
var ErrSharePayloadTooLarge = errors.New("share link payload too large")
var ErrShareExpiryInvalid = errors.New("share link expiry must be between 1 and 72 hours")

// maxSharePayloadBytes limits the opaque client-encrypted payload to 1MB.
const maxSharePayloadBytes = 1 << 20

type ShareLinkService interface {
	Create(ctx context.Context, userID, vaultID, itemID uuid.UUID, req dto.CreateShareLinkRequest) (*models.ShareLink, error)
	List(ctx context.Context, userID, vaultID, itemID uuid.UUID) ([]models.ShareLink, error)
	Delete(ctx context.Context, userID, linkID uuid.UUID) error
	// Redeem is PUBLIC (no auth): atomically consumes the single-use link.
	Redeem(ctx context.Context, linkID uuid.UUID) (string, error)
	// Status is PUBLIC (no auth): reports availability without consuming.
	Status(ctx context.Context, linkID uuid.UUID) (string, error)
}

type shareLinkService struct {
	shareLinkRepo repository.ShareLinkRepository
	vaultRepo     repository.VaultRepository
	itemRepo      repository.ItemRepository
	teamRepo      repository.TeamRepository
}

func NewShareLinkService(
	shareLinkRepo repository.ShareLinkRepository,
	vaultRepo repository.VaultRepository,
	itemRepo repository.ItemRepository,
	teamRepo repository.TeamRepository,
) ShareLinkService {
	return &shareLinkService{
		shareLinkRepo: shareLinkRepo,
		vaultRepo:     vaultRepo,
		itemRepo:      itemRepo,
		teamRepo:      teamRepo,
	}
}

// verifyManage enforces the share-link management policy: for a personal
// vault only the vault OWNER may manage links; for a team vault (owning team
// via vaults.team_id or any team recorded in vault_teams) only ADMINS of an
// associated team may.
func (s *shareLinkService) verifyManage(ctx context.Context, userID, vaultID uuid.UUID) error {
	vault, err := s.vaultRepo.GetByID(ctx, vaultID)
	if err != nil {
		return err
	}

	teamIDs := make(map[uuid.UUID]struct{})
	if vault.TeamID != nil {
		teamIDs[*vault.TeamID] = struct{}{}
	}
	shares, err := s.vaultRepo.ListTeamShares(ctx, vaultID)
	if err != nil {
		return fmt.Errorf("listing vault team shares: %w", err)
	}
	for _, sh := range shares {
		teamIDs[sh.TeamID] = struct{}{}
	}

	// Personal vault: owner only.
	if len(teamIDs) == 0 {
		if vault.OwnerID == userID {
			return nil
		}
		return ErrShareLinkForbidden
	}

	// Team vault: admin of any associated team.
	for teamID := range teamIDs {
		member, err := s.teamRepo.GetMember(ctx, teamID, userID)
		if err == nil && member.Role == "admin" {
			return nil
		}
	}
	return ErrShareLinkForbidden
}

// verifyItemInVault ensures the item exists and belongs to the vault.
func (s *shareLinkService) verifyItemInVault(ctx context.Context, vaultID, itemID uuid.UUID) error {
	item, err := s.itemRepo.GetByID(ctx, itemID)
	if err != nil {
		return err
	}
	if item.VaultID != vaultID {
		return repository.ErrItemNotFound
	}
	return nil
}

func (s *shareLinkService) Create(ctx context.Context, userID, vaultID, itemID uuid.UUID, req dto.CreateShareLinkRequest) (*models.ShareLink, error) {
	if len(req.PayloadEncrypted) == 0 || len(req.PayloadEncrypted) > maxSharePayloadBytes {
		if len(req.PayloadEncrypted) > maxSharePayloadBytes {
			return nil, ErrSharePayloadTooLarge
		}
		return nil, fmt.Errorf("payload_encrypted is required")
	}
	if req.ExpiresInHours < 1 || req.ExpiresInHours > 72 {
		return nil, ErrShareExpiryInvalid
	}

	if err := s.verifyManage(ctx, userID, vaultID); err != nil {
		return nil, err
	}
	if err := s.verifyItemInVault(ctx, vaultID, itemID); err != nil {
		return nil, err
	}

	link := &models.ShareLink{
		VaultID:          vaultID,
		ItemID:           itemID,
		PayloadEncrypted: req.PayloadEncrypted,
		CreatedBy:        userID,
		ExpiresAt:        time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour),
	}
	if err := s.shareLinkRepo.Create(ctx, link); err != nil {
		return nil, fmt.Errorf("creating share link: %w", err)
	}
	return link, nil
}

func (s *shareLinkService) List(ctx context.Context, userID, vaultID, itemID uuid.UUID) ([]models.ShareLink, error) {
	if err := s.verifyManage(ctx, userID, vaultID); err != nil {
		return nil, err
	}
	if err := s.verifyItemInVault(ctx, vaultID, itemID); err != nil {
		return nil, err
	}
	return s.shareLinkRepo.ListByItem(ctx, itemID)
}

func (s *shareLinkService) Delete(ctx context.Context, userID, linkID uuid.UUID) error {
	link, err := s.shareLinkRepo.GetByID(ctx, linkID)
	if err != nil {
		return err
	}

	// The creator may always revoke; otherwise the vault owner/team admin
	// policy applies.
	if link.CreatedBy != userID {
		if err := s.verifyManage(ctx, userID, link.VaultID); err != nil {
			if errors.Is(err, repository.ErrVaultNotFound) {
				return ErrShareLinkForbidden
			}
			return err
		}
	}
	return s.shareLinkRepo.Delete(ctx, linkID)
}

func (s *shareLinkService) Redeem(ctx context.Context, linkID uuid.UUID) (string, error) {
	return s.shareLinkRepo.Redeem(ctx, linkID)
}

func (s *shareLinkService) Status(ctx context.Context, linkID uuid.UUID) (string, error) {
	available, err := s.shareLinkRepo.GetStatus(ctx, linkID)
	if err != nil {
		return "", err
	}
	if available {
		return "available", nil
	}
	return "gone", nil
}
