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

type ShareLinkHandler struct {
	shareLinkService service.ShareLinkService
}

func NewShareLinkHandler(shareLinkService service.ShareLinkService) *ShareLinkHandler {
	return &ShareLinkHandler{shareLinkService: shareLinkService}
}

// Create handles POST /api/vaults/:id/items/:itemId/share-link (auth required).
func (h *ShareLinkHandler) Create(c *gin.Context) {
	vaultID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid vault id"}})
		return
	}
	itemID, err := uuid.Parse(c.Param("itemId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid item id"}})
		return
	}

	var req dto.CreateShareLinkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	userID := middleware.GetUserID(c)
	link, err := h.shareLinkService.Create(c.Request.Context(), userID, vaultID, itemID, req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrShareLinkForbidden), errors.Is(err, repository.ErrVaultNotFound):
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
		case errors.Is(err, repository.ErrItemNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "item not found"}})
		case errors.Is(err, service.ErrSharePayloadTooLarge), errors.Is(err, service.ErrShareExpiryInvalid):
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to create share link"}})
		}
		return
	}

	c.JSON(http.StatusCreated, dto.CreateShareLinkResponse{
		ID:        link.ID.String(),
		ExpiresAt: link.ExpiresAt,
	})
}

// List handles GET /api/vaults/:id/items/:itemId/share-links (auth required).
func (h *ShareLinkHandler) List(c *gin.Context) {
	vaultID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid vault id"}})
		return
	}
	itemID, err := uuid.Parse(c.Param("itemId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid item id"}})
		return
	}

	userID := middleware.GetUserID(c)
	links, err := h.shareLinkService.List(c.Request.Context(), userID, vaultID, itemID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrShareLinkForbidden), errors.Is(err, repository.ErrVaultNotFound):
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
		case errors.Is(err, repository.ErrItemNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "item not found"}})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to list share links"}})
		}
		return
	}

	result := make([]dto.ShareLinkInfo, 0, len(links))
	for _, l := range links {
		result = append(result, dto.ShareLinkInfo{
			ID:         l.ID.String(),
			CreatedAt:  l.CreatedAt,
			ExpiresAt:  l.ExpiresAt,
			RedeemedAt: l.RedeemedAt,
		})
	}
	c.JSON(http.StatusOK, result)
}

// Delete handles DELETE /api/share-links/:id (auth required).
func (h *ShareLinkHandler) Delete(c *gin.Context) {
	linkID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid share link id"}})
		return
	}

	userID := middleware.GetUserID(c)
	if err := h.shareLinkService.Delete(c.Request.Context(), userID, linkID); err != nil {
		switch {
		case errors.Is(err, repository.ErrShareLinkNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "share link not found"}})
		case errors.Is(err, service.ErrShareLinkForbidden):
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to delete share link"}})
		}
		return
	}
	c.Status(http.StatusNoContent)
}

// Redeem handles POST /auth/share-links/:id/redeem (PUBLIC, single use).
func (h *ShareLinkHandler) Redeem(c *gin.Context) {
	linkID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		// An unparseable id never existed.
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "share link not found"}})
		return
	}

	payload, err := h.shareLinkService.Redeem(c.Request.Context(), linkID)
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrShareLinkGone):
			c.JSON(http.StatusGone, gin.H{"error": gin.H{"code": "GONE", "message": "share link already redeemed or expired"}})
		case errors.Is(err, repository.ErrShareLinkNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "share link not found"}})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to redeem share link"}})
		}
		return
	}

	c.JSON(http.StatusOK, dto.RedeemShareLinkResponse{PayloadEncrypted: payload})
}

// Status handles GET /auth/share-links/:id/status (PUBLIC, non-consuming).
func (h *ShareLinkHandler) Status(c *gin.Context) {
	linkID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "share link not found"}})
		return
	}

	status, err := h.shareLinkService.Status(c.Request.Context(), linkID)
	if err != nil {
		if errors.Is(err, repository.ErrShareLinkNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "share link not found"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to get share link status"}})
		return
	}

	c.JSON(http.StatusOK, dto.ShareLinkStatusResponse{Status: status})
}
