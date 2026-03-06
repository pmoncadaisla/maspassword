package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/middleware"
	"github.com/masorange/maspassword/internal/repository"
	"github.com/masorange/maspassword/internal/service"
	"github.com/masorange/maspassword/pkg/dto"
)

type TeamHandler struct {
	teamService service.TeamService
}

func NewTeamHandler(teamService service.TeamService) *TeamHandler {
	return &TeamHandler{teamService: teamService}
}

func (h *TeamHandler) Create(c *gin.Context) {
	var req dto.CreateTeamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	userID := middleware.GetUserID(c)
	team, err := h.teamService.Create(c.Request.Context(), userID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to create team"}})
		return
	}

	c.JSON(http.StatusCreated, team)
}

func (h *TeamHandler) List(c *gin.Context) {
	userID := middleware.GetUserID(c)
	teams, err := h.teamService.ListByUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to list teams"}})
		return
	}
	c.JSON(http.StatusOK, teams)
}

func (h *TeamHandler) Get(c *gin.Context) {
	teamID, err := uuid.Parse(c.Param("teamId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid team id"}})
		return
	}

	userID := middleware.GetUserID(c)
	team, err := h.teamService.GetByID(c.Request.Context(), userID, teamID)
	if err != nil {
		if errors.Is(err, service.ErrNotTeamMember) || errors.Is(err, repository.ErrTeamNotFound) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to get team"}})
		return
	}
	c.JSON(http.StatusOK, team)
}

func (h *TeamHandler) AddMember(c *gin.Context) {
	teamID, err := uuid.Parse(c.Param("teamId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid team id"}})
		return
	}

	var req dto.AddMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	userID := middleware.GetUserID(c)
	member, err := h.teamService.AddMember(c.Request.Context(), userID, teamID, req)
	if err != nil {
		if errors.Is(err, service.ErrNotTeamAdmin) || errors.Is(err, service.ErrNotTeamMember) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "admin access required"}})
			return
		}
		if errors.Is(err, repository.ErrAlreadyMember) {
			c.JSON(http.StatusConflict, gin.H{"error": gin.H{"code": "ALREADY_MEMBER", "message": "user is already a member"}})
			return
		}
		if errors.Is(err, repository.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "user not found"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to add member"}})
		return
	}

	c.JSON(http.StatusCreated, member)
}

func (h *TeamHandler) RemoveMember(c *gin.Context) {
	teamID, err := uuid.Parse(c.Param("teamId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid team id"}})
		return
	}

	targetUserID, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid user id"}})
		return
	}

	userID := middleware.GetUserID(c)
	err = h.teamService.RemoveMember(c.Request.Context(), userID, teamID, targetUserID)
	if err != nil {
		if errors.Is(err, service.ErrNotTeamAdmin) || errors.Is(err, service.ErrNotTeamMember) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "admin access required"}})
			return
		}
		if errors.Is(err, service.ErrCannotRemoveOwner) {
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "CANNOT_REMOVE_OWNER", "message": "cannot remove team owner"}})
			return
		}
		if errors.Is(err, repository.ErrMemberNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "member not found"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to remove member"}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *TeamHandler) UpdateMemberRole(c *gin.Context) {
	teamID, err := uuid.Parse(c.Param("teamId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid team id"}})
		return
	}

	targetUserID, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid user id"}})
		return
	}

	var req dto.UpdateMemberRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	userID := middleware.GetUserID(c)
	err = h.teamService.UpdateMemberRole(c.Request.Context(), userID, teamID, targetUserID, req)
	if err != nil {
		if errors.Is(err, service.ErrNotTeamAdmin) || errors.Is(err, service.ErrNotTeamMember) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "admin access required"}})
			return
		}
		if errors.Is(err, service.ErrCannotChangeOwnerRole) {
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "CANNOT_CHANGE_OWNER", "message": "cannot change owner role"}})
			return
		}
		if errors.Is(err, repository.ErrMemberNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "member not found"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to update member role"}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *TeamHandler) GetPendingVaultKeys(c *gin.Context) {
	teamID, err := uuid.Parse(c.Param("teamId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid team id"}})
		return
	}

	userID := middleware.GetUserID(c)
	pending, err := h.teamService.GetPendingVaultKeys(c.Request.Context(), userID, teamID)
	if err != nil {
		if errors.Is(err, service.ErrNotTeamAdmin) || errors.Is(err, service.ErrNotTeamMember) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "admin access required"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to get pending vault keys"}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"pending": pending})
}

func (h *TeamHandler) ListMembers(c *gin.Context) {
	teamID, err := uuid.Parse(c.Param("teamId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid team id"}})
		return
	}

	userID := middleware.GetUserID(c)
	members, err := h.teamService.ListMembers(c.Request.Context(), userID, teamID)
	if err != nil {
		if errors.Is(err, service.ErrNotTeamMember) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to list members"}})
		return
	}

	c.JSON(http.StatusOK, members)
}
