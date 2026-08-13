package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/repository"
)

// --- In-memory fakes (hermetic, no DB) satisfying the repository interfaces ---

type fakeItemRepo struct {
	items   map[uuid.UUID]*models.Item
	history map[uuid.UUID][]models.ItemHistory
}

func newFakeItemRepo() *fakeItemRepo {
	return &fakeItemRepo{
		items:   make(map[uuid.UUID]*models.Item),
		history: make(map[uuid.UUID][]models.ItemHistory),
	}
}

func (f *fakeItemRepo) Create(_ context.Context, item *models.Item) error {
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	item.Version = 1
	cp := *item
	f.items[item.ID] = &cp
	return nil
}

func (f *fakeItemRepo) GetByID(_ context.Context, id uuid.UUID) (*models.Item, error) {
	it, ok := f.items[id]
	if !ok {
		return nil, repository.ErrItemNotFound
	}
	cp := *it
	return &cp, nil
}

func (f *fakeItemRepo) ListByVault(_ context.Context, vaultID uuid.UUID) ([]models.Item, error) {
	var out []models.Item
	for _, it := range f.items {
		if it.VaultID == vaultID {
			out = append(out, *it)
		}
	}
	return out, nil
}

func (f *fakeItemRepo) Update(_ context.Context, item *models.Item) error {
	existing, ok := f.items[item.ID]
	if !ok {
		return repository.ErrItemNotFound
	}
	if existing.Version != item.Version {
		return repository.ErrVersionConflict
	}
	// Snapshot the prior ciphertext into history before overwriting (ZK-safe).
	f.history[item.ID] = append([]models.ItemHistory{{
		ID:            uuid.New(),
		ItemID:        item.ID,
		DataEncrypted: existing.DataEncrypted,
		Version:       existing.Version,
	}}, f.history[item.ID]...)
	existing.DataEncrypted = item.DataEncrypted
	existing.Version++
	item.Version = existing.Version
	return nil
}

func (f *fakeItemRepo) Delete(_ context.Context, id uuid.UUID) error {
	if _, ok := f.items[id]; !ok {
		return repository.ErrItemNotFound
	}
	delete(f.items, id)
	return nil
}

func (f *fakeItemRepo) ListHistory(_ context.Context, itemID uuid.UUID) ([]models.ItemHistory, error) {
	return f.history[itemID], nil
}

type fakeVaultRepo struct {
	vaults map[uuid.UUID]*models.Vault
}

func newFakeVaultRepo() *fakeVaultRepo {
	return &fakeVaultRepo{vaults: make(map[uuid.UUID]*models.Vault)}
}

func (f *fakeVaultRepo) Create(_ context.Context, vault *models.Vault) error {
	if vault.ID == uuid.Nil {
		vault.ID = uuid.New()
	}
	cp := *vault
	f.vaults[vault.ID] = &cp
	return nil
}

func (f *fakeVaultRepo) GetByID(_ context.Context, id uuid.UUID) (*models.Vault, error) {
	v, ok := f.vaults[id]
	if !ok {
		return nil, repository.ErrVaultNotFound
	}
	cp := *v
	return &cp, nil
}

func (f *fakeVaultRepo) ListByOwner(context.Context, uuid.UUID) ([]models.Vault, error) {
	return nil, nil
}
func (f *fakeVaultRepo) ListAccessible(context.Context, uuid.UUID) ([]models.Vault, error) {
	return nil, nil
}
func (f *fakeVaultRepo) ListByTeam(context.Context, uuid.UUID) ([]models.Vault, error) {
	return nil, nil
}
func (f *fakeVaultRepo) SetTeam(context.Context, uuid.UUID, *uuid.UUID) error {
	return nil
}

type fakeVaultKeyRepo struct {
	keys map[string]*models.VaultKey
}

func newFakeVaultKeyRepo() *fakeVaultKeyRepo {
	return &fakeVaultKeyRepo{keys: make(map[string]*models.VaultKey)}
}

func vkKey(vaultID, userID uuid.UUID) string {
	return vaultID.String() + ":" + userID.String()
}

func (f *fakeVaultKeyRepo) Create(_ context.Context, vk *models.VaultKey) error {
	cp := *vk
	f.keys[vkKey(vk.VaultID, vk.UserID)] = &cp
	return nil
}
func (f *fakeVaultKeyRepo) CreateBatch(ctx context.Context, vaultKeys []models.VaultKey) error {
	for i := range vaultKeys {
		if err := f.Create(ctx, &vaultKeys[i]); err != nil {
			return err
		}
	}
	return nil
}
func (f *fakeVaultKeyRepo) GetByVaultAndUser(_ context.Context, vaultID, userID uuid.UUID) (*models.VaultKey, error) {
	vk, ok := f.keys[vkKey(vaultID, userID)]
	if !ok {
		return nil, repository.ErrVaultKeyNotFound
	}
	cp := *vk
	return &cp, nil
}
func (f *fakeVaultKeyRepo) DeleteByVaultAndUser(_ context.Context, vaultID, userID uuid.UUID) error {
	delete(f.keys, vkKey(vaultID, userID))
	return nil
}
func (f *fakeVaultKeyRepo) ListByVault(context.Context, uuid.UUID) ([]models.VaultKey, error) {
	return nil, nil
}

// fixture wires a service over fresh fakes with a single owner-owned vault + item.
func newItemServiceFixture(t *testing.T) (ItemService, *fakeItemRepo, *fakeVaultRepo, *fakeVaultKeyRepo, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	itemRepo := newFakeItemRepo()
	vaultRepo := newFakeVaultRepo()
	vaultKeyRepo := newFakeVaultKeyRepo()

	owner := uuid.New()
	vaultID := uuid.New()
	itemID := uuid.New()

	vaultRepo.vaults[vaultID] = &models.Vault{ID: vaultID, OwnerID: owner}
	itemRepo.items[itemID] = &models.Item{ID: itemID, VaultID: vaultID, DataEncrypted: "cipher", Version: 1}

	svc := NewItemService(itemRepo, vaultRepo, vaultKeyRepo)
	return svc, itemRepo, vaultRepo, vaultKeyRepo, owner, vaultID, itemID
}

func TestItemService_Delete_HappyPath(t *testing.T) {
	svc, itemRepo, _, _, owner, vaultID, itemID := newItemServiceFixture(t)

	if err := svc.Delete(context.Background(), owner, vaultID, itemID); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if _, ok := itemRepo.items[itemID]; ok {
		t.Fatal("item should have been deleted")
	}
}

func TestItemService_Delete_NotOwner(t *testing.T) {
	svc, itemRepo, _, _, _, vaultID, itemID := newItemServiceFixture(t)
	stranger := uuid.New()

	err := svc.Delete(context.Background(), stranger, vaultID, itemID)
	if !errors.Is(err, ErrNotVaultOwner) {
		t.Fatalf("expected ErrNotVaultOwner, got %v", err)
	}
	if _, ok := itemRepo.items[itemID]; !ok {
		t.Fatal("item must NOT be deleted when access is denied")
	}
}

func TestItemService_Delete_ItemInDifferentVault(t *testing.T) {
	svc, itemRepo, _, _, owner, vaultID, itemID := newItemServiceFixture(t)
	// Move the item to a different vault than the one the caller addresses.
	otherVaultID := uuid.New()
	itemRepo.items[itemID].VaultID = otherVaultID

	err := svc.Delete(context.Background(), owner, vaultID, itemID)
	if !errors.Is(err, repository.ErrItemNotFound) {
		t.Fatalf("expected ErrItemNotFound, got %v", err)
	}
	if _, ok := itemRepo.items[itemID]; !ok {
		t.Fatal("item must NOT be deleted when it belongs to a different vault")
	}
}

func TestItemService_Delete_SharedAccessGranted(t *testing.T) {
	svc, itemRepo, _, vaultKeyRepo, _, vaultID, itemID := newItemServiceFixture(t)
	// A non-owner who holds a vault key (shared access) may delete.
	member := uuid.New()
	vaultKeyRepo.keys[vkKey(vaultID, member)] = &models.VaultKey{VaultID: vaultID, UserID: member}

	if err := svc.Delete(context.Background(), member, vaultID, itemID); err != nil {
		t.Fatalf("expected shared member to delete, got %v", err)
	}
	if _, ok := itemRepo.items[itemID]; ok {
		t.Fatal("item should have been deleted by shared member")
	}
}

func TestItemService_ListHistory_HappyPath(t *testing.T) {
	svc, itemRepo, _, _, owner, vaultID, itemID := newItemServiceFixture(t)
	itemRepo.history[itemID] = []models.ItemHistory{
		{ID: uuid.New(), ItemID: itemID, DataEncrypted: "old-ciphertext", Version: 1},
	}

	history, err := svc.ListHistory(context.Background(), owner, vaultID, itemID)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if len(history) != 1 || history[0].DataEncrypted != "old-ciphertext" {
		t.Fatalf("unexpected history: %+v", history)
	}
}

func TestItemService_ListHistory_AccessDenied(t *testing.T) {
	svc, _, _, _, _, vaultID, itemID := newItemServiceFixture(t)
	stranger := uuid.New()

	_, err := svc.ListHistory(context.Background(), stranger, vaultID, itemID)
	if !errors.Is(err, ErrNotVaultOwner) {
		t.Fatalf("expected ErrNotVaultOwner, got %v", err)
	}
}

func TestItemService_ListHistory_ItemInDifferentVault(t *testing.T) {
	svc, itemRepo, _, _, owner, vaultID, itemID := newItemServiceFixture(t)
	itemRepo.items[itemID].VaultID = uuid.New()

	_, err := svc.ListHistory(context.Background(), owner, vaultID, itemID)
	if !errors.Is(err, repository.ErrItemNotFound) {
		t.Fatalf("expected ErrItemNotFound, got %v", err)
	}
}
