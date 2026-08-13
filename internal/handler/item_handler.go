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

type ItemHandler struct {
	itemService service.ItemService
}

func NewItemHandler(itemService service.ItemService) *ItemHandler {
	return &ItemHandler{itemService: itemService}
}

func (h *ItemHandler) Create(c *gin.Context) {
	vaultID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid vault id"}})
		return
	}

	var req dto.CreateItemRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	userID := middleware.GetUserID(c)
	item, err := h.itemService.Create(c.Request.Context(), userID, vaultID, req)
	if err != nil {
		if errors.Is(err, service.ErrNotVaultOwner) || errors.Is(err, repository.ErrVaultNotFound) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to create item"}})
		return
	}

	c.JSON(http.StatusCreated, item)
}

func (h *ItemHandler) List(c *gin.Context) {
	vaultID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid vault id"}})
		return
	}

	userID := middleware.GetUserID(c)
	items, err := h.itemService.ListByVault(c.Request.Context(), userID, vaultID)
	if err != nil {
		if errors.Is(err, service.ErrNotVaultOwner) || errors.Is(err, repository.ErrVaultNotFound) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to list items"}})
		return
	}

	c.JSON(http.StatusOK, items)
}

func (h *ItemHandler) Update(c *gin.Context) {
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

	var req dto.UpdateItemRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	userID := middleware.GetUserID(c)
	item, err := h.itemService.Update(c.Request.Context(), userID, vaultID, itemID, req)
	if err != nil {
		if errors.Is(err, service.ErrNotVaultOwner) || errors.Is(err, repository.ErrVaultNotFound) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
			return
		}
		if errors.Is(err, repository.ErrVersionConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": gin.H{"code": "VERSION_CONFLICT", "message": "item has been modified, refresh and retry"}})
			return
		}
		if errors.Is(err, repository.ErrItemNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "item not found"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to update item"}})
		return
	}

	c.JSON(http.StatusOK, item)
}

func (h *ItemHandler) Delete(c *gin.Context) {
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
	if err := h.itemService.Delete(c.Request.Context(), userID, vaultID, itemID); err != nil {
		if errors.Is(err, service.ErrNotVaultOwner) || errors.Is(err, repository.ErrVaultNotFound) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
			return
		}
		if errors.Is(err, repository.ErrItemNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "item not found"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to delete item"}})
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *ItemHandler) History(c *gin.Context) {
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
	history, err := h.itemService.ListHistory(c.Request.Context(), userID, vaultID, itemID)
	if err != nil {
		if errors.Is(err, service.ErrNotVaultOwner) || errors.Is(err, repository.ErrVaultNotFound) {
			c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "FORBIDDEN", "message": "access denied"}})
			return
		}
		if errors.Is(err, repository.ErrItemNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "item not found"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to list item history"}})
		return
	}

	c.JSON(http.StatusOK, history)
}
