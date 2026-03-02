package models

import (
	"time"

	"github.com/google/uuid"
)

type Vault struct {
	ID            uuid.UUID  `db:"id" json:"id"`
	OwnerID       uuid.UUID  `db:"owner_id" json:"owner_id"`
	NameEncrypted string     `db:"name_encrypted" json:"name_encrypted"`
	TeamID        *uuid.UUID `db:"team_id" json:"team_id"`
	CreatedAt     time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at" json:"updated_at"`
}
