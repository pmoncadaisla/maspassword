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

var ErrNotVaultOwner = errors.New("not the owner of this vault")

type ItemService interface {
	Create(ctx context.Context, userID, vaultID uuid.UUID, req dto.CreateItemRequest) (*models.Item, error)
	ListByVault(ctx context.Context, userID, vaultID uuid.UUID) ([]models.Item, error)
	Update(ctx context.Context, userID, vaultID, itemID uuid.UUID, req dto.UpdateItemRequest) (*models.Item, error)
	Delete(ctx context.Context, userID, vaultID, itemID uuid.UUID) error
	ListHistory(ctx context.Context, userID, vaultID, itemID uuid.UUID) ([]models.ItemHistory, error)
}

type itemService struct {
	itemRepo     repository.ItemRepository
	vaultRepo    repository.VaultRepository
	vaultKeyRepo repository.VaultKeyRepository
}

func NewItemService(itemRepo repository.ItemRepository, vaultRepo repository.VaultRepository, vaultKeyRepo repository.VaultKeyRepository) ItemService {
	return &itemService{itemRepo: itemRepo, vaultRepo: vaultRepo, vaultKeyRepo: vaultKeyRepo}
}

func (s *itemService) verifyAccess(ctx context.Context, userID, vaultID uuid.UUID) error {
	vault, err := s.vaultRepo.GetByID(ctx, vaultID)
	if err != nil {
		return err
	}
	if vault.OwnerID == userID {
		return nil
	}
	// Check if user has a vault key (shared vault access)
	if s.vaultKeyRepo != nil {
		_, err := s.vaultKeyRepo.GetByVaultAndUser(ctx, vaultID, userID)
		if err == nil {
			return nil
		}
	}
	return ErrNotVaultOwner
}

func (s *itemService) Create(ctx context.Context, userID, vaultID uuid.UUID, req dto.CreateItemRequest) (*models.Item, error) {
	if err := s.verifyAccess(ctx, userID, vaultID); err != nil {
		return nil, err
	}

	item := &models.Item{
		VaultID:       vaultID,
		DataEncrypted: req.DataEncrypted,
	}
	if err := s.itemRepo.Create(ctx, item); err != nil {
		return nil, fmt.Errorf("creating item: %w", err)
	}
	return item, nil
}

func (s *itemService) ListByVault(ctx context.Context, userID, vaultID uuid.UUID) ([]models.Item, error) {
	if err := s.verifyAccess(ctx, userID, vaultID); err != nil {
		return nil, err
	}

	items, err := s.itemRepo.ListByVault(ctx, vaultID)
	if err != nil {
		return nil, fmt.Errorf("listing items: %w", err)
	}
	return items, nil
}

func (s *itemService) Update(ctx context.Context, userID, vaultID, itemID uuid.UUID, req dto.UpdateItemRequest) (*models.Item, error) {
	if err := s.verifyAccess(ctx, userID, vaultID); err != nil {
		return nil, err
	}

	item, err := s.itemRepo.GetByID(ctx, itemID)
	if err != nil {
		return nil, err
	}
	if item.VaultID != vaultID {
		return nil, repository.ErrItemNotFound
	}

	item.DataEncrypted = req.DataEncrypted
	item.Version = req.Version

	if err := s.itemRepo.Update(ctx, item); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *itemService) Delete(ctx context.Context, userID, vaultID, itemID uuid.UUID) error {
	if err := s.verifyAccess(ctx, userID, vaultID); err != nil {
		return err
	}

	item, err := s.itemRepo.GetByID(ctx, itemID)
	if err != nil {
		return err
	}
	if item.VaultID != vaultID {
		return repository.ErrItemNotFound
	}

	return s.itemRepo.Delete(ctx, itemID)
}

func (s *itemService) ListHistory(ctx context.Context, userID, vaultID, itemID uuid.UUID) ([]models.ItemHistory, error) {
	if err := s.verifyAccess(ctx, userID, vaultID); err != nil {
		return nil, err
	}

	item, err := s.itemRepo.GetByID(ctx, itemID)
	if err != nil {
		return nil, err
	}
	if item.VaultID != vaultID {
		return nil, repository.ErrItemNotFound
	}

	return s.itemRepo.ListHistory(ctx, itemID)
}
