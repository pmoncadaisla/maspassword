package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// SettingKeyDefaultTheme is the app_settings key holding the instance-wide
// default UI theme ("light" or "orange").
const SettingKeyDefaultTheme = "default_theme"

// SettingsRepository stores instance-wide key/value settings (app_settings).
type SettingsRepository interface {
	// Get returns the value for key, or "" (no error) when the key is absent.
	Get(ctx context.Context, key string) (string, error)
	// Upsert inserts or updates a key, refreshing updated_at.
	Upsert(ctx context.Context, key, value string) error
}

type settingsRepo struct {
	db *sqlx.DB
}

func NewSettingsRepository(db *sqlx.DB) SettingsRepository {
	return &settingsRepo{db: db}
}

func (r *settingsRepo) Get(ctx context.Context, key string) (string, error) {
	var value string
	err := r.db.GetContext(ctx, &value, "SELECT value FROM app_settings WHERE key = $1", key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("getting setting %q: %w", key, err)
	}
	return value, nil
}

func (r *settingsRepo) Upsert(ctx context.Context, key, value string) error {
	query := `INSERT INTO app_settings (key, value)
	           VALUES ($1, $2)
	           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`
	if _, err := r.db.ExecContext(ctx, query, key, value); err != nil {
		return fmt.Errorf("upserting setting %q: %w", key, err)
	}
	return nil
}
