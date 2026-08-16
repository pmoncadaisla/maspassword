package middleware

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/iap"
	"github.com/masorange/maspassword/internal/names"
	"github.com/masorange/maspassword/internal/repository"
)

const UserIDKey = "user_id"
const AuthMethodKey = "auth_method"

func JWTAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{"code": "UNAUTHORIZED", "message": "missing authorization header"},
			})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{"code": "UNAUTHORIZED", "message": "invalid authorization format"},
			})
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(secret), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{"code": "UNAUTHORIZED", "message": "invalid or expired token"},
			})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{"code": "UNAUTHORIZED", "message": "invalid token claims"},
			})
			return
		}

		userIDStr, ok := claims["user_id"].(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{"code": "UNAUTHORIZED", "message": "invalid user_id in token"},
			})
			return
		}

		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{"code": "UNAUTHORIZED", "message": "invalid user_id format"},
			})
			return
		}

		c.Set(UserIDKey, userID)
		c.Next()
	}
}

func GetUserID(c *gin.Context) uuid.UUID {
	val, _ := c.Get(UserIDKey)
	uid, _ := val.(uuid.UUID)
	return uid
}

func GetAuthMethod(c *gin.Context) string {
	val, _ := c.Get(AuthMethodKey)
	method, _ := val.(string)
	if method == "" {
		return "srp"
	}
	return method
}

// DualAuth supports both IAP JWT (X-Goog-IAP-JWT-Assertion) and Bearer JWT auth.
// If the IAP header is present and the validator is non-nil, it validates the IAP
// token, finds or creates the user, and sets user_id + auth_method="iap".
// Otherwise, it falls back to the standard Bearer JWT flow.
func DualAuth(jwtSecret string, iapValidator *iap.Validator, userRepo repository.UserRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		iapToken := c.GetHeader("X-Goog-IAP-JWT-Assertion")
		if iapToken != "" && iapValidator != nil {
			claims, err := iapValidator.Validate(iapToken)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": gin.H{"code": "UNAUTHORIZED", "message": "invalid IAP token"},
				})
				return
			}

			// Find or create user by email
			user, _, err := userRepo.FindOrCreateByEmail(c.Request.Context(), claims.Email)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": gin.H{"code": "INTERNAL_ERROR", "message": "failed to resolve user"},
				})
				return
			}

			// Backfill the display name once: prefer the IAP "name" claim,
			// otherwise derive it from the email local part. Non-fatal.
			if user.DisplayName == "" {
				name := strings.TrimSpace(claims.Name)
				if name == "" {
					name = names.DeriveFromEmail(claims.Email)
				}
				if name != "" {
					if err := userRepo.UpdateDisplayName(c.Request.Context(), user.ID, name); err != nil {
						log.Printf("failed to set display name for %s: %v", claims.Email, err)
					}
				}
			}

			c.Set(UserIDKey, user.ID)
			c.Set(AuthMethodKey, "iap")
			c.Next()
			return
		}

		// Fallback to Bearer JWT
		JWTAuth(jwtSecret)(c)
	}
}
