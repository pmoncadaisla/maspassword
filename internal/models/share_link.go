package models

import (
	"time"

	"github.com/google/uuid"
)

// ShareLink is a one-time, expiring share of a single item. The payload is
// opaque ciphertext produced by the client; the decryption key only ever
// lives in the URL fragment on the client side (zero-knowledge).
type ShareLink struct {
	ID               uuid.UUID  `db:"id" json:"id"`
	VaultID          uuid.UUID  `db:"vault_id" json:"vault_id"`
	ItemID           uuid.UUID  `db:"item_id" json:"item_id"`
	PayloadEncrypted string     `db:"payload_encrypted" json:"-"`
	CreatedBy        uuid.UUID  `db:"created_by" json:"created_by"`
	CreatedAt        time.Time  `db:"created_at" json:"created_at"`
	ExpiresAt        time.Time  `db:"expires_at" json:"expires_at"`
	RedeemedAt       *time.Time `db:"redeemed_at" json:"redeemed_at"`
}
