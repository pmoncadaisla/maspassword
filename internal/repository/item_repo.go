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

var ErrItemNotFound = errors.New("item not found")
var ErrVersionConflict = errors.New("version conflict")

type ItemRepository interface {
	Create(ctx context.Context, item *models.Item) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Item, error)
	ListByVault(ctx context.Context, vaultID uuid.UUID) ([]models.Item, error)
	Update(ctx context.Context, item *models.Item) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListHistory(ctx context.Context, itemID uuid.UUID) ([]models.ItemHistory, error)
}

type itemRepo struct {
	db *sqlx.DB
}

func NewItemRepository(db *sqlx.DB) ItemRepository {
	return &itemRepo{db: db}
}

func (r *itemRepo) Create(ctx context.Context, item *models.Item) error {
	query := `INSERT INTO items (vault_id, data_encrypted)
	           VALUES ($1, $2)
	           RETURNING id, version, created_at, updated_at`
	err := r.db.QueryRowContext(ctx, query, item.VaultID, item.DataEncrypted).
		Scan(&item.ID, &item.Version, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return fmt.Errorf("creating item: %w", err)
	}
	return nil
}

func (r *itemRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Item, error) {
	var item models.Item
	err := r.db.GetContext(ctx, &item, "SELECT * FROM items WHERE id = $1", id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrItemNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting item by id: %w", err)
	}
	return &item, nil
}

func (r *itemRepo) ListByVault(ctx context.Context, vaultID uuid.UUID) ([]models.Item, error) {
	var items []models.Item
	err := r.db.SelectContext(ctx, &items, "SELECT * FROM items WHERE vault_id = $1 ORDER BY created_at DESC", vaultID)
	if err != nil {
		return nil, fmt.Errorf("listing items: %w", err)
	}
	return items, nil
}

func (r *itemRepo) Update(ctx context.Context, item *models.Item) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning item update transaction: %w", err)
	}

	// Snapshot the CURRENT ciphertext into history BEFORE overwriting it.
	// Zero-Knowledge safe: only the opaque data_encrypted is copied, never decrypted.
	// If the optimistic update below conflicts, the rollback discards this snapshot.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO item_history (item_id, data_encrypted, version)
		 SELECT id, data_encrypted, version FROM items WHERE id = $1`,
		item.ID); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("snapshotting item history: %w", err)
	}

	query := `UPDATE items SET data_encrypted = $1, version = version + 1, updated_at = now()
	           WHERE id = $2 AND version = $3
	           RETURNING version, updated_at`
	err = tx.QueryRowContext(ctx, query, item.DataEncrypted, item.ID, item.Version).
		Scan(&item.Version, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		return ErrVersionConflict
	}
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("updating item: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing item update: %w", err)
	}
	return nil
}

func (r *itemRepo) Delete(ctx context.Context, id uuid.UUID) error {
	res, err := r.db.ExecContext(ctx, "DELETE FROM items WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("deleting item: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("deleting item: %w", err)
	}
	if n == 0 {
		return ErrItemNotFound
	}
	return nil
}

func (r *itemRepo) ListHistory(ctx context.Context, itemID uuid.UUID) ([]models.ItemHistory, error) {
	var history []models.ItemHistory
	err := r.db.SelectContext(ctx, &history, "SELECT * FROM item_history WHERE item_id = $1 ORDER BY created_at DESC", itemID)
	if err != nil {
		return nil, fmt.Errorf("listing item history: %w", err)
	}
	return history, nil
}
