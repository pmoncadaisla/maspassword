package handler

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/masorange/maspassword/internal/repository"
	"github.com/masorange/maspassword/pkg/dto"
)

// Themes selectable as the instance-wide default. "light" is the built-in
// look and always the fallback; "orange" is the Orange Design System skin.
const (
	ThemeLight  = "light"
	ThemeOrange = "orange"
)

// IsValidTheme reports whether v is a selectable theme name.
func IsValidTheme(v string) bool {
	return v == ThemeLight || v == ThemeOrange
}

// NormalizeTheme maps any stored/unknown value to a valid theme, defaulting
// to "light".
func NormalizeTheme(v string) string {
	if IsValidTheme(v) {
		return v
	}
	return ThemeLight
}

// SettingsHandler serves the admin-only global settings endpoints and the
// public default-theme lookup used by /auth/mode.
type SettingsHandler struct {
	repo repository.SettingsRepository
}

func NewSettingsHandler(repo repository.SettingsRepository) *SettingsHandler {
	return &SettingsHandler{repo: repo}
}

// DefaultTheme reads the instance-wide default theme, normalized to a valid
// value. Read errors degrade to "light" (the endpoint stays available even if
// the settings table is briefly unreachable).
func (h *SettingsHandler) DefaultTheme(ctx context.Context) string {
	if h == nil || h.repo == nil {
		return ThemeLight
	}
	value, err := h.repo.Get(ctx, repository.SettingKeyDefaultTheme)
	if err != nil {
		log.Printf("reading default theme: %v", err)
		return ThemeLight
	}
	return NormalizeTheme(value)
}

// GetSettings handles GET /api/admin/settings.
func (h *SettingsHandler) GetSettings(c *gin.Context) {
	c.JSON(http.StatusOK, dto.GlobalSettingsResponse{
		DefaultTheme: h.DefaultTheme(c.Request.Context()),
	})
}

// UpdateSettings handles PUT /api/admin/settings.
func (h *SettingsHandler) UpdateSettings(c *gin.Context) {
	var req dto.UpdateGlobalSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}
	if !IsValidTheme(req.DefaultTheme) {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": "default_theme must be 'light' or 'orange'"}})
		return
	}

	if err := h.repo.Upsert(c.Request.Context(), repository.SettingKeyDefaultTheme, req.DefaultTheme); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "internal error"}})
		return
	}

	c.JSON(http.StatusOK, dto.GlobalSettingsResponse{DefaultTheme: req.DefaultTheme})
}
