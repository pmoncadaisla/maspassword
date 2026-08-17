package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/masorange/maspassword/internal/models"
)

var ErrVaultNotFound = errors.New("vault not found")

// VaultTeamShare is a vault→team share record enriched with the team name.
type VaultTeamShare struct {
	TeamID   uuid.UUID `db:"team_id"`
	TeamName string    `db:"team_name"`
	SharedAt time.Time `db:"shared_at"`
}

type VaultRepository interface {
	Create(ctx context.Context, vault *models.Vault) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Vault, error)
	ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]models.Vault, error)
	ListAccessible(ctx context.Context, userID uuid.UUID) ([]models.Vault, error)
	ListByTeam(ctx context.Context, teamID uuid.UUID) ([]models.Vault, error)
	SetTeam(ctx context.Context, vaultID uuid.UUID, teamID *uuid.UUID) error
	// AddTeamShare records that a vault is shared with a team (idempotent).
	AddTeamShare(ctx context.Context, vaultID, teamID uuid.UUID) error
	ListTeamShares(ctx context.Context, vaultID uuid.UUID) ([]VaultTeamShare, error)
	// Delete removes the vault; items, history, vault keys, team shares and
	// share links all go with it via ON DELETE CASCADE.
	Delete(ctx context.Context, id uuid.UUID) error
}

type vaultRepo struct {
	db *sqlx.DB
}

func NewVaultRepository(db *sqlx.DB) VaultRepository {
	return &vaultRepo{db: db}
}

func (r *vaultRepo) Create(ctx context.Context, vault *models.Vault) error {
	query := `INSERT INTO vaults (owner_id, name_encrypted, team_id)
	           VALUES ($1, $2, $3)
	           RETURNING id, created_at, updated_at`
	err := r.db.QueryRowContext(ctx, query, vault.OwnerID, vault.NameEncrypted, vault.TeamID).
		Scan(&vault.ID, &vault.CreatedAt, &vault.UpdatedAt)
	if err != nil {
		return fmt.Errorf("creating vault: %w", err)
	}
	return nil
}

func (r *vaultRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Vault, error) {
	var vault models.Vault
	err := r.db.GetContext(ctx, &vault, "SELECT * FROM vaults WHERE id = $1", id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrVaultNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting vault by id: %w", err)
	}
	return &vault, nil
}

func (r *vaultRepo) ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]models.Vault, error) {
	var vaults []models.Vault
	err := r.db.SelectContext(ctx, &vaults, "SELECT * FROM vaults WHERE owner_id = $1 ORDER BY created_at DESC", ownerID)
	if err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}
	return vaults, nil
}

func (r *vaultRepo) ListAccessible(ctx context.Context, userID uuid.UUID) ([]models.Vault, error) {
	var vaults []models.Vault
	query := `SELECT DISTINCT v.* FROM vaults v
	          LEFT JOIN vault_keys vk ON vk.vault_id = v.id AND vk.user_id = $1
	          WHERE v.owner_id = $1 OR vk.user_id = $1
	          ORDER BY v.created_at DESC`
	err := r.db.SelectContext(ctx, &vaults, query, userID)
	if err != nil {
		return nil, fmt.Errorf("listing accessible vaults: %w", err)
	}
	return vaults, nil
}

func (r *vaultRepo) ListByTeam(ctx context.Context, teamID uuid.UUID) ([]models.Vault, error) {
	var vaults []models.Vault
	err := r.db.SelectContext(ctx, &vaults, "SELECT * FROM vaults WHERE team_id = $1 ORDER BY created_at DESC", teamID)
	if err != nil {
		return nil, fmt.Errorf("listing team vaults: %w", err)
	}
	return vaults, nil
}

func (r *vaultRepo) SetTeam(ctx context.Context, vaultID uuid.UUID, teamID *uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "UPDATE vaults SET team_id = $1, updated_at = now() WHERE id = $2", teamID, vaultID)
	if err != nil {
		return fmt.Errorf("setting vault team: %w", err)
	}
	return nil
}

func (r *vaultRepo) AddTeamShare(ctx context.Context, vaultID, teamID uuid.UUID) error {
	query := `INSERT INTO vault_teams (vault_id, team_id) VALUES ($1, $2)
	           ON CONFLICT (vault_id, team_id) DO NOTHING`
	if _, err := r.db.ExecContext(ctx, query, vaultID, teamID); err != nil {
		return fmt.Errorf("recording vault team share: %w", err)
	}
	return nil
}

func (r *vaultRepo) ListTeamShares(ctx context.Context, vaultID uuid.UUID) ([]VaultTeamShare, error) {
	var shares []VaultTeamShare
	query := `SELECT vt.team_id, t.name AS team_name, vt.shared_at
	          FROM vault_teams vt
	          JOIN teams t ON t.id = vt.team_id
	          WHERE vt.vault_id = $1
	          ORDER BY vt.shared_at ASC`
	if err := r.db.SelectContext(ctx, &shares, query, vaultID); err != nil {
		return nil, fmt.Errorf("listing vault team shares: %w", err)
	}
	return shares, nil
}

func (r *vaultRepo) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM vaults WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("deleting vault: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("deleting vault: %w", err)
	}
	if rows == 0 {
		return ErrVaultNotFound
	}
	return nil
}
