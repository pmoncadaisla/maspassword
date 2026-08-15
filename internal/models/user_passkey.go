package models

import (
	"time"

	"github.com/google/uuid"
)

// UserPasskey is a WebAuthn credential that signs into MasPassword itself.
// PRFEncryptedEncKey carries the user's encryption key wrapped by a key
// derived from the credential's PRF output; the server never sees either
// side in the clear.
type UserPasskey struct {
	ID                 uuid.UUID  `db:"id" json:"id"`
	UserID             uuid.UUID  `db:"user_id" json:"-"`
	Name               string     `db:"name" json:"name"`
	CredentialID       string     `db:"credential_id" json:"credential_id"`
	PublicKey          string     `db:"public_key" json:"-"`
	SignCount          int64      `db:"sign_count" json:"-"`
	Transports         string     `db:"transports" json:"-"`
	PRFSalt            string     `db:"prf_salt" json:"-"`
	PRFEncryptedEncKey string     `db:"prf_encrypted_enc_key" json:"-"`
	CreatedAt          time.Time  `db:"created_at" json:"created_at"`
	LastUsedAt         *time.Time `db:"last_used_at" json:"last_used_at"`
}
