package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                  uuid.UUID `db:"id" json:"id"`
	Email               string    `db:"email" json:"email"`
	SRPSalt             *string   `db:"srp_salt" json:"-"`
	SRPVerifier         *string   `db:"srp_verifier" json:"-"`
	PublicKey           *string   `db:"public_key" json:"-"`
	EncryptedPrivateKey         *string   `db:"encrypted_private_key" json:"-"`
	RecoveryEncryptedPrivateKey *string   `db:"recovery_encrypted_private_key" json:"-"`
	CreatedAt                   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt           time.Time `db:"updated_at" json:"updated_at"`
}
