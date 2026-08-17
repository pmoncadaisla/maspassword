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

type VaultHandler struct {
	vaultService service.VaultService
}

func NewVaultHandler(vaultService service.VaultService) *VaultHandler {
	return &VaultHandler{vaultService: vaultService}
}

func (h *VaultHandler) Create(c *gin.Context) {
	var req dto.CreateVaultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	userID := middleware.GetUserID(c)
	vault, err := h.vaultService.Create(c.Request.Context(), userID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to create vault"}})
		return
	}

	c.JSON(http.StatusCreated, vault)
}

func (h *VaultHandler) List(c *gin.Context) {
	userID := middleware.GetUserID(c)
	vaults, err := h.vaultService.ListAccessible(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to list vaults"}})
		return
	}

	c.JSON(http.StatusOK, vaults)
}

func (h *VaultHandler) CreateTeamVault(c *gin.Context) {
	teamID, err := uuid.Parse(c.Param("teamId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid team id"}})
		return
	}

	var req dto.CreateTeamVaultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	userID := middleware.GetUserID(c)
	vault, err := h.vaultService.CreateTeamVault(c.Request.Context(), userID, teamID, req)
	if err != nil {
		if errors.Is(err, service.ErrNotTeamMember) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to create team vault"}})
		return
	}

	c.JSON(http.StatusCreated, vault)
}

func (h *VaultHandler) GetVaultKey(c *gin.Context) {
	vaultID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid vault id"}})
		return
	}

	userID := middleware.GetUserID(c)
	resp, err := h.vaultService.GetVaultKey(c.Request.Context(), userID, vaultID)
	if err != nil {
		if errors.Is(err, service.ErrNoVaultAccess) || errors.Is(err, repository.ErrVaultKeyNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "vault key not found"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to get vault key"}})
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *VaultHandler) ShareVault(c *gin.Context) {
	vaultID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid vault id"}})
		return
	}

	var req dto.ShareVaultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	userID := middleware.GetUserID(c)
	err = h.vaultService.ShareVault(c.Request.Context(), userID, vaultID, req)
	if err != nil {
		if errors.Is(err, service.ErrNoVaultAccess) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to share vault"}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *VaultHandler) ListByTeam(c *gin.Context) {
	teamID, err := uuid.Parse(c.Param("teamId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid team id"}})
		return
	}

	userID := middleware.GetUserID(c)
	vaults, err := h.vaultService.ListByTeam(c.Request.Context(), userID, teamID)
	if err != nil {
		if errors.Is(err, service.ErrNotTeamMember) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to list team vaults"}})
		return
	}

	c.JSON(http.StatusOK, vaults)
}

// Delete handles DELETE /api/vaults/:id. The service enforces who may delete
// (owner, or a team admin for team vaults); everything inside the vault goes
// with it.
func (h *VaultHandler) Delete(c *gin.Context) {
	vaultID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid vault id"}})
		return
	}

	userID := middleware.GetUserID(c)
	if err := h.vaultService.Delete(c.Request.Context(), userID, vaultID); err != nil {
		if errors.Is(err, repository.ErrVaultNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "vault not found"}})
			return
		}
		if errors.Is(err, service.ErrNoVaultAccess) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to delete vault"}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// ListShares handles GET /api/vaults/:id/shares — teams this vault is shared with.
func (h *VaultHandler) ListShares(c *gin.Context) {
	vaultID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid vault id"}})
		return
	}

	userID := middleware.GetUserID(c)
	shares, err := h.vaultService.ListShares(c.Request.Context(), userID, vaultID)
	if err != nil {
		if errors.Is(err, service.ErrNoVaultAccess) || errors.Is(err, repository.ErrVaultNotFound) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to list vault shares"}})
		return
	}

	c.JSON(http.StatusOK, shares)
}
