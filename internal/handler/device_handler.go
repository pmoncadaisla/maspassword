package handler

import (
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/devicetoken"
	"github.com/masorange/maspassword/internal/middleware"
	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/repository"
	"github.com/masorange/maspassword/pkg/dto"
)

const maxDeviceNameLen = 60

// DeviceHandler manages linked-device API tokens. The plaintext token is
// returned exactly once at creation; afterwards only metadata is served.
type DeviceHandler struct {
	repo repository.DeviceTokenRepository
}

func NewDeviceHandler(repo repository.DeviceTokenRepository) *DeviceHandler {
	return &DeviceHandler{repo: repo}
}

// Create handles POST /api/devices.
func (h *DeviceHandler) Create(c *gin.Context) {
	var req dto.CreateDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || utf8.RuneCountInString(name) > maxDeviceNameLen {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": "name must be 1-60 characters"}})
		return
	}

	id, token, hash, err := devicetoken.Generate()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to generate device token"}})
		return
	}

	row := &models.DeviceToken{
		ID:        id,
		UserID:    middleware.GetUserID(c),
		Name:      name,
		TokenHash: hash,
	}
	if err := h.repo.Create(c.Request.Context(), row); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to create device"}})
		return
	}

	c.JSON(http.StatusCreated, dto.CreateDeviceResponse{
		ID:    id.String(),
		Name:  name,
		Token: token,
	})
}

// List handles GET /api/devices.
func (h *DeviceHandler) List(c *gin.Context) {
	tokens, err := h.repo.ListByUser(c.Request.Context(), middleware.GetUserID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to list devices"}})
		return
	}

	out := make([]dto.DeviceResponse, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, dto.DeviceResponse{
			ID:         t.ID.String(),
			Name:       t.Name,
			CreatedAt:  t.CreatedAt,
			LastUsedAt: t.LastUsedAt,
			RevokedAt:  t.RevokedAt,
		})
	}
	c.JSON(http.StatusOK, out)
}

// Revoke handles DELETE /api/devices/:id (owner only, sets revoked_at).
func (h *DeviceHandler) Revoke(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ID", "message": "invalid device id"}})
		return
	}

	err = h.repo.Revoke(c.Request.Context(), id, middleware.GetUserID(c))
	if errors.Is(err, repository.ErrDeviceTokenNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "device not found"}})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to revoke device"}})
		return
	}

	c.Status(http.StatusNoContent)
}
