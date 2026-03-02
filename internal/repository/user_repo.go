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

var ErrUserNotFound = errors.New("user not found")
var ErrEmailExists = errors.New("email already exists")

type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateKeys(ctx context.Context, userID uuid.UUID, publicKey, encryptedPrivateKey string) error
	GetPublicKey(ctx context.Context, userID uuid.UUID) (string, error)
	GetPublicKeysByIDs(ctx context.Context, userIDs []uuid.UUID) (map[uuid.UUID]string, error)
}

type userRepo struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) UserRepository {
	return &userRepo{db: db}
}

func (r *userRepo) Create(ctx context.Context, user *models.User) error {
	query := `INSERT INTO users (email, srp_salt, srp_verifier, public_key, encrypted_private_key)
	           VALUES ($1, $2, $3, $4, $5)
	           RETURNING id, created_at, updated_at`
	err := r.db.QueryRowContext(ctx, query, user.Email, user.SRPSalt, user.SRPVerifier, user.PublicKey, user.EncryptedPrivateKey).
		Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrEmailExists
		}
		return fmt.Errorf("creating user: %w", err)
	}
	return nil
}

func (r *userRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	err := r.db.GetContext(ctx, &user, "SELECT * FROM users WHERE id = $1", id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting user by id: %w", err)
	}
	return &user, nil
}

func (r *userRepo) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.db.GetContext(ctx, &user, "SELECT * FROM users WHERE email = $1", email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting user by email: %w", err)
	}
	return &user, nil
}

func (r *userRepo) UpdateKeys(ctx context.Context, userID uuid.UUID, publicKey, encryptedPrivateKey string) error {
	query := `UPDATE users SET public_key = $1, encrypted_private_key = $2, updated_at = now() WHERE id = $3`
	result, err := r.db.ExecContext(ctx, query, publicKey, encryptedPrivateKey, userID)
	if err != nil {
		return fmt.Errorf("updating user keys: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (r *userRepo) GetPublicKey(ctx context.Context, userID uuid.UUID) (string, error) {
	var publicKey sql.NullString
	err := r.db.QueryRowContext(ctx, "SELECT public_key FROM users WHERE id = $1", userID).Scan(&publicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrUserNotFound
	}
	if err != nil {
		return "", fmt.Errorf("getting public key: %w", err)
	}
	if !publicKey.Valid {
		return "", fmt.Errorf("user has no public key")
	}
	return publicKey.String, nil
}

func (r *userRepo) GetPublicKeysByIDs(ctx context.Context, userIDs []uuid.UUID) (map[uuid.UUID]string, error) {
	if len(userIDs) == 0 {
		return map[uuid.UUID]string{}, nil
	}
	query, args, err := sqlx.In("SELECT id, public_key FROM users WHERE id IN (?) AND public_key IS NOT NULL", userIDs)
	if err != nil {
		return nil, fmt.Errorf("building query: %w", err)
	}
	query = r.db.Rebind(query)

	type row struct {
		ID        uuid.UUID `db:"id"`
		PublicKey string    `db:"public_key"`
	}
	var rows []row
	if err := r.db.SelectContext(ctx, &rows, query, args...); err != nil {
		return nil, fmt.Errorf("getting public keys: %w", err)
	}
	result := make(map[uuid.UUID]string, len(rows))
	for _, r := range rows {
		result[r.ID] = r.PublicKey
	}
	return result, nil
}

func isUniqueViolation(err error) bool {
	return err != nil && (err.Error() == "pq: duplicate key value violates unique constraint \"users_email_key\"" ||
		err.Error() == "pq: duplicate key value violates unique constraint \"idx_users_email\"")
}
