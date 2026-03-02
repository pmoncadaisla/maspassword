package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/repository"
	"github.com/masorange/maspassword/pkg/dto"
)

var ErrNotTeamAdmin = errors.New("not a team admin")
var ErrNotTeamMember = errors.New("not a team member")
var ErrCannotRemoveOwner = errors.New("cannot remove team owner")

type TeamService interface {
	Create(ctx context.Context, ownerID uuid.UUID, req dto.CreateTeamRequest) (*models.Team, error)
	GetByID(ctx context.Context, userID, teamID uuid.UUID) (*models.Team, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]models.Team, error)
	AddMember(ctx context.Context, adminID, teamID uuid.UUID, req dto.AddMemberRequest) (*models.TeamMember, error)
	RemoveMember(ctx context.Context, adminID, teamID, targetUserID uuid.UUID) error
	ListMembers(ctx context.Context, userID, teamID uuid.UUID) ([]repository.TeamMemberWithEmail, error)
}

type teamService struct {
	teamRepo repository.TeamRepository
	userRepo repository.UserRepository
}

func NewTeamService(teamRepo repository.TeamRepository, userRepo repository.UserRepository) TeamService {
	return &teamService{teamRepo: teamRepo, userRepo: userRepo}
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

	// Find user by email
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	member := &models.TeamMember{
		TeamID: teamID,
		UserID: user.ID,
		Role:   "member",
	}
	if err := s.teamRepo.AddMember(ctx, member); err != nil {
		return nil, err
	}
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
