package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/masorange/maspassword/internal/models"
)

var ErrVaultKeyNotFound = errors.New("vault key not found")

type VaultKeyRepository interface {
	Create(ctx context.Context, vk *models.VaultKey) error
	CreateBatch(ctx context.Context, vaultKeys []models.VaultKey) error
	GetByVaultAndUser(ctx context.Context, vaultID, userID uuid.UUID) (*models.VaultKey, error)
	DeleteByVaultAndUser(ctx context.Context, vaultID, userID uuid.UUID) error
	ListByVault(ctx context.Context, vaultID uuid.UUID) ([]models.VaultKey, error)
}

type vaultKeyRepo struct {
	db *sqlx.DB
}

func NewVaultKeyRepository(db *sqlx.DB) VaultKeyRepository {
	return &vaultKeyRepo{db: db}
}

func (r *vaultKeyRepo) Create(ctx context.Context, vk *models.VaultKey) error {
	query := `INSERT INTO vault_keys (vault_id, user_id, encrypted_vault_key)
	           VALUES ($1, $2, $3)
	           RETURNING id, created_at`
	err := r.db.QueryRowContext(ctx, query, vk.VaultID, vk.UserID, vk.EncryptedVaultKey).
		Scan(&vk.ID, &vk.CreatedAt)
	if err != nil {
		return fmt.Errorf("creating vault key: %w", err)
	}
	return nil
}

func (r *vaultKeyRepo) CreateBatch(ctx context.Context, vaultKeys []models.VaultKey) error {
	for i := range vaultKeys {
		if err := r.Create(ctx, &vaultKeys[i]); err != nil {
			return err
		}
	}
	return nil
}

func (r *vaultKeyRepo) GetByVaultAndUser(ctx context.Context, vaultID, userID uuid.UUID) (*models.VaultKey, error) {
	var vk models.VaultKey
	err := r.db.GetContext(ctx, &vk, "SELECT * FROM vault_keys WHERE vault_id = $1 AND user_id = $2", vaultID, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrVaultKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting vault key: %w", err)
	}
	return &vk, nil
}

func (r *vaultKeyRepo) DeleteByVaultAndUser(ctx context.Context, vaultID, userID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM vault_keys WHERE vault_id = $1 AND user_id = $2", vaultID, userID)
	if err != nil {
		return fmt.Errorf("deleting vault key: %w", err)
	}
	return nil
}

func (r *vaultKeyRepo) ListByVault(ctx context.Context, vaultID uuid.UUID) ([]models.VaultKey, error) {
	var vks []models.VaultKey
	err := r.db.SelectContext(ctx, &vks, "SELECT * FROM vault_keys WHERE vault_id = $1 ORDER BY created_at ASC", vaultID)
	if err != nil {
		return nil, fmt.Errorf("listing vault keys: %w", err)
	}
	return vks, nil
}
