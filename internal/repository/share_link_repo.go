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

var ErrShareLinkNotFound = errors.New("share link not found")
var ErrShareLinkGone = errors.New("share link already redeemed or expired")

type ShareLinkRepository interface {
	Create(ctx context.Context, link *models.ShareLink) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ShareLink, error)
	ListByItem(ctx context.Context, itemID uuid.UUID) ([]models.ShareLink, error)
	// Redeem atomically marks the link as redeemed and returns its payload.
	// Returns ErrShareLinkGone if already redeemed or expired, and
	// ErrShareLinkNotFound if the link never existed.
	Redeem(ctx context.Context, id uuid.UUID) (string, error)
	// GetStatus reports whether the link is still redeemable without
	// consuming it. Returns ErrShareLinkNotFound if the link never existed.
	GetStatus(ctx context.Context, id uuid.UUID) (bool, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type shareLinkRepo struct {
	db *sqlx.DB
}

func NewShareLinkRepository(db *sqlx.DB) ShareLinkRepository {
	return &shareLinkRepo{db: db}
}

func (r *shareLinkRepo) Create(ctx context.Context, link *models.ShareLink) error {
	query := `INSERT INTO share_links (vault_id, item_id, payload_encrypted, created_by, expires_at)
	           VALUES ($1, $2, $3, $4, $5)
	           RETURNING id, created_at, expires_at`
	err := r.db.QueryRowContext(ctx, query,
		link.VaultID, link.ItemID, link.PayloadEncrypted, link.CreatedBy, link.ExpiresAt).
		Scan(&link.ID, &link.CreatedAt, &link.ExpiresAt)
	if err != nil {
		return fmt.Errorf("creating share link: %w", err)
	}
	return nil
}

func (r *shareLinkRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.ShareLink, error) {
	var link models.ShareLink
	err := r.db.GetContext(ctx, &link, "SELECT * FROM share_links WHERE id = $1", id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrShareLinkNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting share link: %w", err)
	}
	return &link, nil
}

func (r *shareLinkRepo) ListByItem(ctx context.Context, itemID uuid.UUID) ([]models.ShareLink, error) {
	var links []models.ShareLink
	query := "SELECT * FROM share_links WHERE item_id = $1 ORDER BY created_at DESC"
	if err := r.db.SelectContext(ctx, &links, query, itemID); err != nil {
		return nil, fmt.Errorf("listing share links: %w", err)
	}
	return links, nil
}

func (r *shareLinkRepo) Redeem(ctx context.Context, id uuid.UUID) (string, error) {
	var payload string
	query := `UPDATE share_links SET redeemed_at = now()
	           WHERE id = $1 AND redeemed_at IS NULL AND expires_at > now()
	           RETURNING payload_encrypted`
	err := r.db.QueryRowContext(ctx, query, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		// Distinguish "gone" (redeemed/expired) from "never existed".
		var exists bool
		if err2 := r.db.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM share_links WHERE id = $1)", id).Scan(&exists); err2 != nil {
			return "", fmt.Errorf("checking share link existence: %w", err2)
		}
		if exists {
			return "", ErrShareLinkGone
		}
		return "", ErrShareLinkNotFound
	}
	if err != nil {
		return "", fmt.Errorf("redeeming share link: %w", err)
	}
	return payload, nil
}

func (r *shareLinkRepo) GetStatus(ctx context.Context, id uuid.UUID) (bool, error) {
	var available bool
	query := "SELECT (redeemed_at IS NULL AND expires_at > now()) FROM share_links WHERE id = $1"
	err := r.db.QueryRowContext(ctx, query, id).Scan(&available)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrShareLinkNotFound
	}
	if err != nil {
		return false, fmt.Errorf("getting share link status: %w", err)
	}
	return available, nil
}

func (r *shareLinkRepo) Delete(ctx context.Context, id uuid.UUID) error {
	res, err := r.db.ExecContext(ctx, "DELETE FROM share_links WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("deleting share link: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("deleting share link: %w", err)
	}
	if n == 0 {
		return ErrShareLinkNotFound
	}
	return nil
}
