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

// ItemWithAuthor is an item enriched with the email/display name of the user
// who last modified it (empty strings when unknown).
type ItemWithAuthor struct {
	models.Item
	UpdatedByEmail string `db:"updated_by_email" json:"updated_by_email"`
	UpdatedByName  string `db:"updated_by_name" json:"updated_by_name"`
}

// ItemHistoryWithAuthor is a history entry enriched with the email/display
// name of the user who authored the archived version (empty strings when unknown).
type ItemHistoryWithAuthor struct {
	models.ItemHistory
	ChangedByEmail string `db:"changed_by_email" json:"changed_by_email"`
	ChangedByName  string `db:"changed_by_name" json:"changed_by_name"`
}

type ItemRepository interface {
	Create(ctx context.Context, item *models.Item) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Item, error)
	ListByVault(ctx context.Context, vaultID uuid.UUID) ([]ItemWithAuthor, error)
	Update(ctx context.Context, item *models.Item) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListHistory(ctx context.Context, itemID uuid.UUID) ([]ItemHistoryWithAuthor, error)
}

type itemRepo struct {
	db *sqlx.DB
}

func NewItemRepository(db *sqlx.DB) ItemRepository {
	return &itemRepo{db: db}
}

func (r *itemRepo) Create(ctx context.Context, item *models.Item) error {
	query := `INSERT INTO items (vault_id, data_encrypted, updated_by)
	           VALUES ($1, $2, $3)
	           RETURNING id, version, created_at, updated_at`
	err := r.db.QueryRowContext(ctx, query, item.VaultID, item.DataEncrypted, item.UpdatedBy).
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

func (r *itemRepo) ListByVault(ctx context.Context, vaultID uuid.UUID) ([]ItemWithAuthor, error) {
	var items []ItemWithAuthor
	query := `SELECT i.*,
	                 COALESCE(u.email, '') AS updated_by_email,
	                 COALESCE(u.display_name, '') AS updated_by_name
	          FROM items i
	          LEFT JOIN users u ON u.id = i.updated_by
	          WHERE i.vault_id = $1
	          ORDER BY i.created_at DESC`
	err := r.db.SelectContext(ctx, &items, query, vaultID)
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
	// changed_by records who authored the version being archived (the old row's
	// updated_by, which may be NULL for pre-audit rows).
	// If the optimistic update below conflicts, the rollback discards this snapshot.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO item_history (item_id, data_encrypted, version, changed_by)
		 SELECT id, data_encrypted, version, updated_by FROM items WHERE id = $1`,
		item.ID); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("snapshotting item history: %w", err)
	}

	query := `UPDATE items SET data_encrypted = $1, version = version + 1, updated_at = now(), updated_by = $4
	           WHERE id = $2 AND version = $3
	           RETURNING version, updated_at`
	err = tx.QueryRowContext(ctx, query, item.DataEncrypted, item.ID, item.Version, item.UpdatedBy).
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

func (r *itemRepo) ListHistory(ctx context.Context, itemID uuid.UUID) ([]ItemHistoryWithAuthor, error) {
	var history []ItemHistoryWithAuthor
	query := `SELECT h.*,
	                 COALESCE(u.email, '') AS changed_by_email,
	                 COALESCE(u.display_name, '') AS changed_by_name
	          FROM item_history h
	          LEFT JOIN users u ON u.id = h.changed_by
	          WHERE h.item_id = $1
	          ORDER BY h.created_at DESC`
	err := r.db.SelectContext(ctx, &history, query, itemID)
	if err != nil {
		return nil, fmt.Errorf("listing item history: %w", err)
	}
	return history, nil
}
