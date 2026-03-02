package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/middleware"
	"github.com/masorange/maspassword/internal/repository"
)

type UserHandler struct {
	userRepo repository.UserRepository
}

func NewUserHandler(userRepo repository.UserRepository) *UserHandler {
	return &UserHandler{userRepo: userRepo}
}

type uploadKeysRequest struct {
	PublicKey           string `json:"public_key" binding:"required"`
	EncryptedPrivateKey string `json:"encrypted_private_key" binding:"required"`
}

func (h *UserHandler) UploadKeys(c *gin.Context) {
	var req uploadKeysRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	userID := middleware.GetUserID(c)
	if err := h.userRepo.UpdateKeys(c.Request.Context(), userID, req.PublicKey, req.EncryptedPrivateKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to upload keys"}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *UserHandler) GetPublicKey(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid user id"}})
		return
	}

	publicKey, err := h.userRepo.GetPublicKey(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "public key not found"}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"public_key": publicKey})
}
