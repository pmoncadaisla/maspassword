package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/audit"
	"github.com/masorange/maspassword/internal/middleware"
)

func auditTestRouter(userID uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(middleware.UserIDKey, userID) })
	r.POST("/api/audit", NewAuditHandler().Report)
	return r
}

func postAudit(t *testing.T, r *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/audit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAuditReport(t *testing.T) {
	uid := uuid.New()
	vaultID := uuid.New().String()
	itemID := uuid.New().String()

	var buf bytes.Buffer
	audit.SetOutput(&buf)
	t.Cleanup(func() { audit.SetOutput(nil) })
	r := auditTestRouter(uid)

	t.Run("valid secret_viewed event is emitted with source client", func(t *testing.T) {
		buf.Reset()
		w := postAudit(t, r, `{"action":"item.secret_viewed","vault_id":"`+vaultID+`","item_id":"`+itemID+`","field":"password"}`)
		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
		}
		var ev map[string]any
		if err := json.Unmarshal(buf.Bytes(), &ev); err != nil {
			t.Fatalf("no valid audit line: %v", err)
		}
		if ev["action"] != "item.secret_viewed" || ev["source"] != "client" ||
			ev["vault_id"] != vaultID || ev["item_id"] != itemID ||
			ev["field"] != "password" || ev["user_id"] != uid.String() {
			t.Fatalf("bad event: %v", ev)
		}
	})

	t.Run("export event carries format and count", func(t *testing.T) {
		buf.Reset()
		w := postAudit(t, r, `{"action":"vault.exported","vault_id":"`+vaultID+`","format":"kdbx","count":12}`)
		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", w.Code)
		}
		var ev map[string]any
		if err := json.Unmarshal(buf.Bytes(), &ev); err != nil {
			t.Fatalf("no valid audit line: %v", err)
		}
		if ev["format"] != "kdbx" || ev["count"] != float64(12) {
			t.Fatalf("bad event: %v", ev)
		}
	})

	rejected := map[string]string{
		"unknown action":    `{"action":"item.password_leaked"}`,
		"missing action":    `{}`,
		"non-UUID vault_id": `{"action":"vault.exported","vault_id":"../../etc"}`,
		"non-UUID item_id":  `{"action":"item.secret_viewed","item_id":"x"}`,
		"free-text field":   `{"action":"item.secret_viewed","field":"algo con espacios!"}`,
		"unknown format":    `{"action":"vault.exported","format":"xlsx"}`,
	}
	for name, body := range rejected {
		t.Run("rejects "+name, func(t *testing.T) {
			buf.Reset()
			w := postAudit(t, r, body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", w.Code)
			}
			if buf.Len() != 0 {
				t.Fatalf("rejected request must emit nothing, got %q", buf.String())
			}
		})
	}
}
