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

var ErrPasskeyNotFound = errors.New("passkey not found")

// PasskeyRepository persists login passkeys (user_passkeys).
type PasskeyRepository interface {
	Create(ctx context.Context, p *models.UserPasskey) error
	ListByUser(ctx context.Context, userID uuid.UUID) ([]models.UserPasskey, error)
	GetByCredentialID(ctx context.Context, credentialID string) (*models.UserPasskey, error)
	// Delete is owner-scoped: rows of other users are not found.
	Delete(ctx context.Context, id, userID uuid.UUID) error
	// TouchUsed updates the sign counter and last_used_at after a login.
	TouchUsed(ctx context.Context, id uuid.UUID, signCount int64) error
}

type passkeyRepo struct {
	db *sqlx.DB
}

func NewPasskeyRepository(db *sqlx.DB) PasskeyRepository {
	return &passkeyRepo{db: db}
}

func (r *passkeyRepo) Create(ctx context.Context, p *models.UserPasskey) error {
	query := `INSERT INTO user_passkeys
	            (id, user_id, name, credential_id, public_key, sign_count, transports, prf_salt, prf_encrypted_enc_key)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	          RETURNING created_at`
	if err := r.db.QueryRowContext(ctx, query,
		p.ID, p.UserID, p.Name, p.CredentialID, p.PublicKey, p.SignCount, p.Transports, p.PRFSalt, p.PRFEncryptedEncKey,
	).Scan(&p.CreatedAt); err != nil {
		return fmt.Errorf("creating passkey: %w", err)
	}
	return nil
}

func (r *passkeyRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.UserPasskey, error) {
	var out []models.UserPasskey
	err := r.db.SelectContext(ctx, &out,
		"SELECT * FROM user_passkeys WHERE user_id = $1 ORDER BY created_at", userID)
	if err != nil {
		return nil, fmt.Errorf("listing passkeys: %w", err)
	}
	return out, nil
}

func (r *passkeyRepo) GetByCredentialID(ctx context.Context, credentialID string) (*models.UserPasskey, error) {
	var p models.UserPasskey
	err := r.db.GetContext(ctx, &p, "SELECT * FROM user_passkeys WHERE credential_id = $1", credentialID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPasskeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting passkey: %w", err)
	}
	return &p, nil
}

func (r *passkeyRepo) Delete(ctx context.Context, id, userID uuid.UUID) error {
	res, err := r.db.ExecContext(ctx,
		"DELETE FROM user_passkeys WHERE id = $1 AND user_id = $2", id, userID)
	if err != nil {
		return fmt.Errorf("deleting passkey: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrPasskeyNotFound
	}
	return nil
}

func (r *passkeyRepo) TouchUsed(ctx context.Context, id uuid.UUID, signCount int64) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE user_passkeys SET sign_count = $2, last_used_at = now() WHERE id = $1", id, signCount)
	if err != nil {
		return fmt.Errorf("touching passkey: %w", err)
	}
	return nil
}
