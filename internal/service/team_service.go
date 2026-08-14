package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/mailer"
	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/repository"
	"github.com/masorange/maspassword/pkg/dto"
)

var ErrNotTeamAdmin = errors.New("not a team admin")
var ErrNotTeamMember = errors.New("not a team member")
var ErrCannotRemoveOwner = errors.New("cannot remove team owner")
var ErrCannotChangeOwnerRole = errors.New("cannot change owner role")

type TeamService interface {
	Create(ctx context.Context, ownerID uuid.UUID, req dto.CreateTeamRequest) (*models.Team, error)
	GetByID(ctx context.Context, userID, teamID uuid.UUID) (*models.Team, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]models.Team, error)
	AddMember(ctx context.Context, adminID, teamID uuid.UUID, req dto.AddMemberRequest) (*models.TeamMember, error)
	RemoveMember(ctx context.Context, adminID, teamID, targetUserID uuid.UUID) error
	UpdateMemberRole(ctx context.Context, adminID, teamID, targetUserID uuid.UUID, req dto.UpdateMemberRoleRequest) error
	ListMembers(ctx context.Context, userID, teamID uuid.UUID) ([]repository.TeamMemberWithEmail, error)
	GetPendingVaultKeys(ctx context.Context, adminID, teamID uuid.UUID) ([]dto.PendingVaultKeyInfo, error)
}

type teamService struct {
	teamRepo repository.TeamRepository
	userRepo repository.UserRepository
	mailer   *mailer.Mailer
}

// NewTeamService builds the team service. The mailer may be nil or disabled;
// notifications then become logging no-ops and never affect API calls.
func NewTeamService(teamRepo repository.TeamRepository, userRepo repository.UserRepository, m *mailer.Mailer) TeamService {
	return &teamService{
		teamRepo: teamRepo,
		userRepo: userRepo,
		mailer:   m,
	}
}

func (s *teamService) Create(ctx context.Context, ownerID uuid.UUID, req dto.CreateTeamRequest) (*models.Team, error) {
	team := &models.Team{
		Name:    req.Name,
		OwnerID: ownerID,
	}
	if err := s.teamRepo.Create(ctx, team); err != nil {
		return nil, fmt.Errorf("creating team: %w", err)
	}

	// Auto-add creator as admin
	member := &models.TeamMember{
		TeamID: team.ID,
		UserID: ownerID,
		Role:   "admin",
	}
	if err := s.teamRepo.AddMember(ctx, member); err != nil {
		return nil, fmt.Errorf("adding owner as member: %w", err)
	}

	return team, nil
}

func (s *teamService) GetByID(ctx context.Context, userID, teamID uuid.UUID) (*models.Team, error) {
	isMember, err := s.teamRepo.IsMember(ctx, teamID, userID)
	if err != nil {
		return nil, err
	}
	if !isMember {
		return nil, ErrNotTeamMember
	}
	return s.teamRepo.GetByID(ctx, teamID)
}

func (s *teamService) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.Team, error) {
	return s.teamRepo.ListByUser(ctx, userID)
}

func (s *teamService) AddMember(ctx context.Context, adminID, teamID uuid.UUID, req dto.AddMemberRequest) (*models.TeamMember, error) {
	if err := s.verifyAdmin(ctx, adminID, teamID); err != nil {
		return nil, err
	}

	// Find or create placeholder user by email
	user, err := s.userRepo.FindOrCreateByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("finding or creating user: %w", err)
	}

	member := &models.TeamMember{
		TeamID: teamID,
		UserID: user.ID,
		Role:   "member",
	}
	if err := s.teamRepo.AddMember(ctx, member); err != nil {
		return nil, err
	}

	// Notify by email in the background; never blocks or fails the API call.
	s.notifyMemberAdded(teamID, adminID, user, member.Role)

	return member, nil
}

func (s *teamService) RemoveMember(ctx context.Context, adminID, teamID, targetUserID uuid.UUID) error {
	if err := s.verifyAdmin(ctx, adminID, teamID); err != nil {
		return err
	}

	// Check if target is owner
	team, err := s.teamRepo.GetByID(ctx, teamID)
	if err != nil {
		return err
	}
	if team.OwnerID == targetUserID {
		return ErrCannotRemoveOwner
	}

	return s.teamRepo.RemoveMember(ctx, teamID, targetUserID)
}

func (s *teamService) UpdateMemberRole(ctx context.Context, adminID, teamID, targetUserID uuid.UUID, req dto.UpdateMemberRoleRequest) error {
	if err := s.verifyAdmin(ctx, adminID, teamID); err != nil {
		return err
	}

	team, err := s.teamRepo.GetByID(ctx, teamID)
	if err != nil {
		return err
	}
	if team.OwnerID == targetUserID {
		return ErrCannotChangeOwnerRole
	}

	if err := s.teamRepo.UpdateMemberRole(ctx, teamID, targetUserID, req.Role); err != nil {
		return err
	}

	// Notify admins and the promoted user in the background.
	if req.Role == "admin" {
		s.notifyPromoted(teamID, adminID, targetUserID)
	}
	return nil
}

func (s *teamService) ListMembers(ctx context.Context, userID, teamID uuid.UUID) ([]repository.TeamMemberWithEmail, error) {
	isMember, err := s.teamRepo.IsMember(ctx, teamID, userID)
	if err != nil {
		return nil, err
	}
	if !isMember {
		return nil, ErrNotTeamMember
	}
	return s.teamRepo.ListMembers(ctx, teamID)
}

func (s *teamService) GetPendingVaultKeys(ctx context.Context, adminID, teamID uuid.UUID) ([]dto.PendingVaultKeyInfo, error) {
	if err := s.verifyAdmin(ctx, adminID, teamID); err != nil {
		return nil, err
	}

	pending, err := s.teamRepo.GetMembersWithoutVaultKeys(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("getting pending vault keys: %w", err)
	}

	result := make([]dto.PendingVaultKeyInfo, len(pending))
	for i, p := range pending {
		result[i] = dto.PendingVaultKeyInfo{
			UserID:    p.UserID.String(),
			VaultID:   p.VaultID.String(),
			PublicKey: p.PublicKey,
		}
	}
	return result, nil
}

func (s *teamService) verifyAdmin(ctx context.Context, userID, teamID uuid.UUID) error {
	member, err := s.teamRepo.GetMember(ctx, teamID, userID)
	if err != nil {
		return ErrNotTeamMember
	}
	if member.Role != "admin" {
		return ErrNotTeamAdmin
	}
	return nil
}

// displayOrEmail falls back to the email when the display name is empty.
func displayOrEmail(name, email string) string {
	if name != "" {
		return name
	}
	return email
}

// notifyMemberAdded emails the new member (invite) and every team admin
// except the actor. Runs in a goroutine; errors are only logged.
func (s *teamService) notifyMemberAdded(teamID, actorID uuid.UUID, member *models.User, role string) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("panic in member-added notification: %v", r)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		team, err := s.teamRepo.GetByID(ctx, teamID)
		if err != nil {
			log.Printf("notify member added: getting team: %v", err)
			return
		}
		actor, err := s.userRepo.GetByID(ctx, actorID)
		if err != nil {
			log.Printf("notify member added: getting actor: %v", err)
			return
		}
		actorName := displayOrEmail(actor.DisplayName, actor.Email)
		memberName := displayOrEmail(member.DisplayName, member.Email)

		if err := s.mailer.SendMemberInvited(ctx, member.Email, team.Name, actorName, role); err != nil {
			log.Printf("sending invite email to %s: %v", member.Email, err)
		}

		admins, err := s.teamRepo.ListMembers(ctx, teamID)
		if err != nil {
			log.Printf("notify member added: listing members: %v", err)
			return
		}
		for _, m := range admins {
			if m.Role != "admin" || m.UserID == actorID {
				continue
			}
			if err := s.mailer.SendAdminsMemberAdded(ctx, m.Email, team.Name, actorName, memberName, role); err != nil {
				log.Printf("sending admin notification to %s: %v", m.Email, err)
			}
		}
	}()
}

// notifyPromoted emails every team admin and the promoted user after a
// promotion to admin. Runs in a goroutine; errors are only logged.
func (s *teamService) notifyPromoted(teamID, actorID, promotedID uuid.UUID) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("panic in promotion notification: %v", r)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		team, err := s.teamRepo.GetByID(ctx, teamID)
		if err != nil {
			log.Printf("notify promoted: getting team: %v", err)
			return
		}
		actor, err := s.userRepo.GetByID(ctx, actorID)
		if err != nil {
			log.Printf("notify promoted: getting actor: %v", err)
			return
		}
		promoted, err := s.userRepo.GetByID(ctx, promotedID)
		if err != nil {
			log.Printf("notify promoted: getting promoted user: %v", err)
			return
		}
		actorName := displayOrEmail(actor.DisplayName, actor.Email)
		promotedName := displayOrEmail(promoted.DisplayName, promoted.Email)

		members, err := s.teamRepo.ListMembers(ctx, teamID)
		if err != nil {
			log.Printf("notify promoted: listing members: %v", err)
			return
		}
		recipients := map[string]struct{}{promoted.Email: {}}
		for _, m := range members {
			if m.Role == "admin" {
				recipients[m.Email] = struct{}{}
			}
		}
		for email := range recipients {
			if err := s.mailer.SendAdminsPromoted(ctx, email, team.Name, actorName, promotedName); err != nil {
				log.Printf("sending promotion notification to %s: %v", email, err)
			}
		}
	}()
}
