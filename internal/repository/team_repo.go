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

var ErrTeamNotFound = errors.New("team not found")
var ErrMemberNotFound = errors.New("team member not found")
var ErrAlreadyMember = errors.New("user is already a team member")

type TeamMemberWithEmail struct {
	models.TeamMember
	Email        string `db:"email" json:"email"`
	HasPublicKey bool   `db:"has_public_key" json:"has_public_key"`
}

type MemberPendingVaultKey struct {
	UserID    uuid.UUID `db:"user_id"`
	VaultID   uuid.UUID `db:"vault_id"`
	PublicKey string    `db:"public_key"`
}

type TeamRepository interface {
	Create(ctx context.Context, team *models.Team) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Team, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]models.Team, error)
	AddMember(ctx context.Context, member *models.TeamMember) error
	RemoveMember(ctx context.Context, teamID, userID uuid.UUID) error
	GetMember(ctx context.Context, teamID, userID uuid.UUID) (*models.TeamMember, error)
	UpdateMemberRole(ctx context.Context, teamID, userID uuid.UUID, role string) error
	ListMembers(ctx context.Context, teamID uuid.UUID) ([]TeamMemberWithEmail, error)
	IsMember(ctx context.Context, teamID, userID uuid.UUID) (bool, error)
	ListMemberIDs(ctx context.Context, teamID uuid.UUID) ([]uuid.UUID, error)
	GetMembersWithoutVaultKeys(ctx context.Context, teamID uuid.UUID) ([]MemberPendingVaultKey, error)
}

type teamRepo struct {
	db *sqlx.DB
}

func NewTeamRepository(db *sqlx.DB) TeamRepository {
	return &teamRepo{db: db}
}

func (r *teamRepo) Create(ctx context.Context, team *models.Team) error {
	query := `INSERT INTO teams (name, owner_id) VALUES ($1, $2) RETURNING id, created_at, updated_at`
	err := r.db.QueryRowContext(ctx, query, team.Name, team.OwnerID).
		Scan(&team.ID, &team.CreatedAt, &team.UpdatedAt)
	if err != nil {
		return fmt.Errorf("creating team: %w", err)
	}
	return nil
}

func (r *teamRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Team, error) {
	var team models.Team
	err := r.db.GetContext(ctx, &team, "SELECT * FROM teams WHERE id = $1", id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTeamNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting team: %w", err)
	}
	return &team, nil
}

func (r *teamRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.Team, error) {
	var teams []models.Team
	query := `SELECT t.* FROM teams t
	          JOIN team_members tm ON tm.team_id = t.id
	          WHERE tm.user_id = $1
	          ORDER BY t.created_at DESC`
	err := r.db.SelectContext(ctx, &teams, query, userID)
	if err != nil {
		return nil, fmt.Errorf("listing teams: %w", err)
	}
	return teams, nil
}

func (r *teamRepo) AddMember(ctx context.Context, member *models.TeamMember) error {
	query := `INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3) RETURNING id, joined_at`
	err := r.db.QueryRowContext(ctx, query, member.TeamID, member.UserID, member.Role).
		Scan(&member.ID, &member.JoinedAt)
	if err != nil {
		if isTeamMemberUniqueViolation(err) {
			return ErrAlreadyMember
		}
		return fmt.Errorf("adding team member: %w", err)
	}
	return nil
}

func (r *teamRepo) RemoveMember(ctx context.Context, teamID, userID uuid.UUID) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM team_members WHERE team_id = $1 AND user_id = $2", teamID, userID)
	if err != nil {
		return fmt.Errorf("removing team member: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrMemberNotFound
	}
	return nil
}

func (r *teamRepo) UpdateMemberRole(ctx context.Context, teamID, userID uuid.UUID, role string) error {
	result, err := r.db.ExecContext(ctx, "UPDATE team_members SET role = $1 WHERE team_id = $2 AND user_id = $3", role, teamID, userID)
	if err != nil {
		return fmt.Errorf("updating member role: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrMemberNotFound
	}
	return nil
}

func (r *teamRepo) GetMember(ctx context.Context, teamID, userID uuid.UUID) (*models.TeamMember, error) {
	var member models.TeamMember
	err := r.db.GetContext(ctx, &member, "SELECT * FROM team_members WHERE team_id = $1 AND user_id = $2", teamID, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMemberNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting team member: %w", err)
	}
	return &member, nil
}

func (r *teamRepo) ListMembers(ctx context.Context, teamID uuid.UUID) ([]TeamMemberWithEmail, error) {
	var members []TeamMemberWithEmail
	query := `SELECT tm.*, u.email, (u.public_key IS NOT NULL) as has_public_key FROM team_members tm
	          JOIN users u ON u.id = tm.user_id
	          WHERE tm.team_id = $1
	          ORDER BY tm.joined_at ASC`
	err := r.db.SelectContext(ctx, &members, query, teamID)
	if err != nil {
		return nil, fmt.Errorf("listing team members: %w", err)
	}
	return members, nil
}

func (r *teamRepo) IsMember(ctx context.Context, teamID, userID uuid.UUID) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM team_members WHERE team_id = $1 AND user_id = $2", teamID, userID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("checking membership: %w", err)
	}
	return count > 0, nil
}

func (r *teamRepo) ListMemberIDs(ctx context.Context, teamID uuid.UUID) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := r.db.SelectContext(ctx, &ids, "SELECT user_id FROM team_members WHERE team_id = $1", teamID)
	if err != nil {
		return nil, fmt.Errorf("listing member ids: %w", err)
	}
	return ids, nil
}

func (r *teamRepo) GetMembersWithoutVaultKeys(ctx context.Context, teamID uuid.UUID) ([]MemberPendingVaultKey, error) {
	var results []MemberPendingVaultKey
	query := `SELECT tm.user_id, v.id as vault_id, u.public_key
	          FROM team_members tm
	          JOIN vaults v ON v.team_id = tm.team_id
	          JOIN users u ON u.id = tm.user_id
	          LEFT JOIN vault_keys vk ON vk.vault_id = v.id AND vk.user_id = tm.user_id
	          WHERE tm.team_id = $1
	            AND u.public_key IS NOT NULL
	            AND vk.id IS NULL`
	err := r.db.SelectContext(ctx, &results, query, teamID)
	if err != nil {
		return nil, fmt.Errorf("getting members without vault keys: %w", err)
	}
	return results, nil
}

func isTeamMemberUniqueViolation(err error) bool {
	return err != nil && err.Error() == "pq: duplicate key value violates unique constraint \"team_members_team_id_user_id_key\""
}
