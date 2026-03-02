package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/masorange/maspassword/internal/middleware"
	"github.com/masorange/maspassword/internal/service"
	"github.com/masorange/maspassword/pkg/dto"
)

type AuthHandler struct {
	authService service.AuthService
}

func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Signup(c *gin.Context) {
	var req dto.SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	resp, err := h.authService.Signup(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": gin.H{"code": "SIGNUP_FAILED", "message": "signup failed"}})
		return
	}

	c.JSON(http.StatusCreated, resp)
}

func (h *AuthHandler) LoginStep1(c *gin.Context) {
	var req dto.LoginStep1Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	resp, err := h.authService.LoginStep1(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "internal error"}})
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) LoginStep2(c *gin.Context) {
	var req dto.LoginStep2Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	resp, err := h.authService.LoginStep2(c.Request.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) || errors.Is(err, service.ErrSessionNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": gin.H{"code": "AUTH_FAILED", "message": "authentication failed"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "internal error"}})
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) GetSession(c *gin.Context) {
	userID := middleware.GetUserID(c)

	resp, err := h.authService.GetSessionInfo(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "internal error"}})
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) SetupEncryption(c *gin.Context) {
	var req dto.SetupEncryptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	userID := middleware.GetUserID(c)

	if err := h.authService.SetupEncryption(c.Request.Context(), userID, req); err != nil {
		if err.Error() == "encryption already set up" {
			c.JSON(http.StatusConflict, gin.H{"error": gin.H{"code": "ALREADY_SETUP", "message": "encryption already set up"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "internal error"}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
