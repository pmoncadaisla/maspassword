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

var ErrDeviceTokenNotFound = errors.New("device token not found")

// DeviceTokenRepository persists linked-device API tokens (device_tokens).
// Only token hashes are stored — never plaintext tokens.
type DeviceTokenRepository interface {
	Create(ctx context.Context, t *models.DeviceToken) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.DeviceToken, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]models.DeviceToken, error)
	// Revoke marks the token revoked. Owner-scoped: rows of other users are
	// not found. Idempotent — the original revoked_at is preserved.
	Revoke(ctx context.Context, id, userID uuid.UUID) error
	// TouchLastUsed sets last_used_at = now(). Best-effort bookkeeping.
	TouchLastUsed(ctx context.Context, id uuid.UUID) error
}

type deviceTokenRepo struct {
	db *sqlx.DB
}

func NewDeviceTokenRepository(db *sqlx.DB) DeviceTokenRepository {
	return &deviceTokenRepo{db: db}
}

func (r *deviceTokenRepo) Create(ctx context.Context, t *models.DeviceToken) error {
	query := `INSERT INTO device_tokens (id, user_id, name, token_hash)
	           VALUES ($1, $2, $3, $4)
	           RETURNING created_at`
	if err := r.db.QueryRowContext(ctx, query, t.ID, t.UserID, t.Name, t.TokenHash).Scan(&t.CreatedAt); err != nil {
		return fmt.Errorf("creating device token: %w", err)
	}
	return nil
}

func (r *deviceTokenRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.DeviceToken, error) {
	var t models.DeviceToken
	err := r.db.GetContext(ctx, &t, "SELECT * FROM device_tokens WHERE id = $1", id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDeviceTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting device token: %w", err)
	}
	return &t, nil
}

func (r *deviceTokenRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.DeviceToken, error) {
	tokens := []models.DeviceToken{}
	err := r.db.SelectContext(ctx, &tokens,
		"SELECT * FROM device_tokens WHERE user_id = $1 ORDER BY created_at DESC", userID)
	if err != nil {
		return nil, fmt.Errorf("listing device tokens: %w", err)
	}
	return tokens, nil
}

func (r *deviceTokenRepo) Revoke(ctx context.Context, id, userID uuid.UUID) error {
	query := `UPDATE device_tokens SET revoked_at = COALESCE(revoked_at, now())
	           WHERE id = $1 AND user_id = $2`
	result, err := r.db.ExecContext(ctx, query, id, userID)
	if err != nil {
		return fmt.Errorf("revoking device token: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrDeviceTokenNotFound
	}
	return nil
}

func (r *deviceTokenRepo) TouchLastUsed(ctx context.Context, id uuid.UUID) error {
	if _, err := r.db.ExecContext(ctx, "UPDATE device_tokens SET last_used_at = now() WHERE id = $1", id); err != nil {
		return fmt.Errorf("updating device token last_used_at: %w", err)
	}
	return nil
}
