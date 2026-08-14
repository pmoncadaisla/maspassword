package models

import (
	"time"

	"github.com/google/uuid"
)

// DeviceToken is a long-lived API token for a linked mobile device.
// Only the SHA-256 hash of the token is stored; the plaintext token is shown
// exactly once at creation time. The token authenticates the device against
// the API — it carries no key material (zero-knowledge: the phone derives
// the encryption keys locally from the master password).
type DeviceToken struct {
	ID         uuid.UUID  `db:"id" json:"id"`
	UserID     uuid.UUID  `db:"user_id" json:"user_id"`
	Name       string     `db:"name" json:"name"`
	TokenHash  string     `db:"token_hash" json:"-"`
	CreatedAt  time.Time  `db:"created_at" json:"created_at"`
	LastUsedAt *time.Time `db:"last_used_at" json:"last_used_at"`
	RevokedAt  *time.Time `db:"revoked_at" json:"revoked_at"`
}
