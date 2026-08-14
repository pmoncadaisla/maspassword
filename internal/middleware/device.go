package middleware

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/masorange/maspassword/internal/devicetoken"
	"github.com/masorange/maspassword/internal/repository"
)

// deviceTouchInterval throttles last_used_at refreshes: the column is only
// updated when the previous value is older than this (or NULL).
const deviceTouchInterval = 60 * time.Second

// DeviceTokenAuth authenticates "mpd_..." bearer tokens issued to linked
// mobile devices. Any other request (JWT bearer, IAP header, missing auth)
// is delegated untouched to fallback — JWTAuth or DualAuth — so device
// tokens work identically in both modes.
//
// On success it sets the SAME auth context the JWT path sets (user_id),
// plus auth_method="device", and refreshes last_used_at best-effort.
func DeviceTokenAuth(repo repository.DeviceTokenRepository, fallback gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, isDevice := bearerDeviceToken(c.GetHeader("Authorization"))
		if !isDevice {
			fallback(c)
			return
		}

		id, ok := devicetoken.ParseID(raw)
		if !ok {
			deviceUnauthorized(c, "invalid device token")
			return
		}

		row, err := repo.GetByID(c.Request.Context(), id)
		if errors.Is(err, repository.ErrDeviceTokenNotFound) {
			deviceUnauthorized(c, "invalid device token")
			return
		}
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to verify device token"},
			})
			return
		}

		// Constant-time comparison of the stored hash vs. the hash of the
		// presented token (both fixed-length hex strings).
		if !devicetoken.HashEqual(row.TokenHash, devicetoken.Hash(raw)) {
			deviceUnauthorized(c, "invalid device token")
			return
		}
		if row.RevokedAt != nil {
			deviceUnauthorized(c, "device token revoked")
			return
		}

		c.Set(UserIDKey, row.UserID)
		c.Set(AuthMethodKey, "device")

		// Best-effort last-used bookkeeping, throttled to once per interval.
		if row.LastUsedAt == nil || time.Since(*row.LastUsedAt) >= deviceTouchInterval {
			if err := repo.TouchLastUsed(c.Request.Context(), row.ID); err != nil {
				log.Printf("device token %s: updating last_used_at: %v", row.ID, err)
			}
		}

		c.Next()
	}
}

// bearerDeviceToken returns the bearer value when the Authorization header
// carries a device token ("Bearer mpd_...").
func bearerDeviceToken(header string) (string, bool) {
	token := strings.TrimPrefix(header, "Bearer ")
	if token == header || !strings.HasPrefix(token, devicetoken.Prefix) {
		return "", false
	}
	return token, true
}

func deviceUnauthorized(c *gin.Context, msg string) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error": gin.H{"code": "UNAUTHORIZED", "message": msg},
	})
}
