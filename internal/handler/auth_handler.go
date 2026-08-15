package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/masorange/maspassword/internal/config"
	"github.com/masorange/maspassword/internal/middleware"
	"github.com/masorange/maspassword/internal/service"
	"github.com/masorange/maspassword/pkg/dto"
)

type AuthHandler struct {
	authService           service.AuthService
	adminEmails           config.AdminEmails // zero value: nobody is admin
	signupDisabled        bool               // zero value: signup enabled
	passwordLoginDisabled bool               // zero value: SRP login enabled
}

func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// SetAdminEmails configures the admin set used to flag sessions with is_admin.
func (h *AuthHandler) SetAdminEmails(adminEmails config.AdminEmails) {
	h.adminEmails = adminEmails
}

// SetSignupEnabled toggles public signup (SIGNUP_ENABLED env; default on).
// SSO-only deployments set it to false so accounts are provisioned only
// through the identity provider.
func (h *AuthHandler) SetSignupEnabled(enabled bool) {
	h.signupDisabled = !enabled
}

// SetPasswordLoginEnabled toggles SRP email/master-password login
// (PASSWORD_LOGIN env; default on). When disabled, both login steps return
// 403 so nobody can probe SRP against other people's emails; clients read
// the same flag from /auth/mode and hide the email form.
func (h *AuthHandler) SetPasswordLoginEnabled(enabled bool) {
	h.passwordLoginDisabled = !enabled
}

func (h *AuthHandler) rejectIfPasswordLoginDisabled(c *gin.Context) bool {
	if !h.passwordLoginDisabled {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "PASSWORD_LOGIN_DISABLED", "message": "password login is disabled; use SSO"}})
	return true
}

func (h *AuthHandler) Signup(c *gin.Context) {
	if h.signupDisabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "signup disabled"})
		return
	}

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
	if h.rejectIfPasswordLoginDisabled(c) {
		return
	}
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
	if h.rejectIfPasswordLoginDisabled(c) {
		return
	}
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
	resp.IsAdmin = h.adminEmails.Contains(resp.Email)

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

func (h *AuthHandler) GetRecoveryData(c *gin.Context) {
	email := c.Param("email")
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": "email is required"}})
		return
	}

	resp, err := h.authService.GetRecoveryData(c.Request.Context(), email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "recovery data not available"}})
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) RecoverChallenge(c *gin.Context) {
	var req dto.RecoverChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	resp, err := h.authService.GetRecoveryChallenge(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "internal error"}})
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) Recover(c *gin.Context) {
	var req dto.RecoverRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	if err := h.authService.Recover(c.Request.Context(), req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "RECOVERY_FAILED", "message": "recovery failed"}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
