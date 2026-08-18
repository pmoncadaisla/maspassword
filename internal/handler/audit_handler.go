package handler

import (
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/audit"
	"github.com/masorange/maspassword/internal/middleware"
)

// AuditHandler ingests audit events for actions only the client can observe
// under zero-knowledge: revealing/copying a decrypted secret, exporting or
// importing a vault. Everything is validated against whitelists so the log
// stream cannot be polluted with arbitrary strings; ids must be UUIDs. The
// payload carries metadata only — no field values ever travel here.
type AuditHandler struct{}

func NewAuditHandler() *AuditHandler {
	return &AuditHandler{}
}

var clientAuditActions = map[string]bool{
	"item.secret_viewed": true,
	"item.secret_copied": true,
	"item.totp_copied":   true,
	"vault.exported":     true,
	"vault.imported":     true,
}

var (
	auditFieldRe  = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	auditFormatRe = regexp.MustCompile(`^(kdbx|csv|json|1pif)$`)
)

type auditReportRequest struct {
	Action  string `json:"action" binding:"required"`
	VaultID string `json:"vault_id"`
	ItemID  string `json:"item_id"`
	Field   string `json:"field"`
	Format  string `json:"format"`
	Count   int    `json:"count"`
}

func (h *AuditHandler) Report(c *gin.Context) {
	var req auditReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}
	if !clientAuditActions[req.Action] {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "INVALID_ACTION", "message": "unknown audit action"}})
		return
	}

	fields := map[string]any{
		"user_id":    middleware.GetUserID(c).String(),
		"ip":         c.ClientIP(),
		"user_agent": c.Request.UserAgent(),
	}
	for name, value := range map[string]string{"vault_id": req.VaultID, "item_id": req.ItemID} {
		if value == "" {
			continue
		}
		if _, err := uuid.Parse(value); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": name + " must be a UUID"}})
			return
		}
		fields[name] = value
	}
	if req.Field != "" {
		if !auditFieldRe.MatchString(req.Field) {
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": "invalid field name"}})
			return
		}
		fields["field"] = req.Field
	}
	if req.Format != "" {
		if !auditFormatRe.MatchString(req.Format) {
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": "invalid format"}})
			return
		}
		fields["format"] = req.Format
	}
	if req.Count > 0 && req.Count <= 1_000_000 {
		fields["count"] = req.Count
	}

	audit.Emit(req.Action, "client", fields)
	c.Status(http.StatusNoContent)
}
