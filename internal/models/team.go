package models

import (
	"time"

	"github.com/google/uuid"
)

type Team struct {
	ID        uuid.UUID `db:"id" json:"id"`
	Name      string    `db:"name" json:"name"`
	OwnerID   uuid.UUID `db:"owner_id" json:"owner_id"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

type TeamMember struct {
	ID       uuid.UUID `db:"id" json:"id"`
	TeamID   uuid.UUID `db:"team_id" json:"team_id"`
	UserID   uuid.UUID `db:"user_id" json:"user_id"`
	Role     string    `db:"role" json:"role"`
	JoinedAt time.Time `db:"joined_at" json:"joined_at"`
}
