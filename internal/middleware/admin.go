package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/masorange/maspassword/internal/config"
	"github.com/masorange/maspassword/internal/repository"
)

// AdminOnly gates a route group to administrators. It runs AFTER the regular
// auth middleware (which sets user_id): it resolves the session user's email
// and rejects with 403 unless it belongs to the ADMIN_EMAILS set.
// An empty admin set rejects everyone.
func AdminOnly(userRepo repository.UserRepository, adminEmails config.AdminEmails) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserID(c)

		user, err := userRepo.GetByID(c.Request.Context(), userID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": gin.H{"code": "FORBIDDEN", "message": "admin access required"},
			})
			return
		}

		if !adminEmails.Contains(user.Email) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": gin.H{"code": "FORBIDDEN", "message": "admin access required"},
			})
			return
		}

		c.Next()
	}
}
