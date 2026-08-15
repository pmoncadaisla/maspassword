package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/masorange/maspassword/internal/middleware"
	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/passkey"
	"github.com/masorange/maspassword/internal/repository"
	"github.com/masorange/maspassword/internal/service"
)

// PasskeyHandler implements passkey login for MasPassword itself: WebAuthn
// assertions authenticate, and the PRF-wrapped encryption key stored at
// registration lets the CLIENT decrypt without a master password. The
// server only ever sees the wrapped blob.
type PasskeyHandler struct {
	repo       repository.PasskeyRepository
	jwtSecret  []byte
	appBaseURL string
}

func NewPasskeyHandler(repo repository.PasskeyRepository, jwtSecret, appBaseURL string) *PasskeyHandler {
	return &PasskeyHandler{
		repo:       repo,
		jwtSecret:  []byte(jwtSecret),
		appBaseURL: strings.TrimSuffix(appBaseURL, "/"),
	}
}

// baseURL mirrors the SSO handler: APP_BASE_URL when set, otherwise
// scheme+host from the request (X-Forwarded-Proto aware).
func (h *PasskeyHandler) baseURL(c *gin.Context) string {
	if h.appBaseURL != "" {
		return h.appBaseURL
	}
	scheme := "http"
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if c.Request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host
}

// rpID is the WebAuthn relying-party id: the hostname, no scheme or port.
func (h *PasskeyHandler) rpID(c *gin.Context) string {
	u, err := url.Parse(h.baseURL(c))
	if err != nil {
		return c.Request.Host
	}
	return u.Hostname()
}

const challengeUse = "passkey_login"
const challengeTTL = 2 * time.Minute

// Challenge handles POST /auth/passkey/challenge (public). The random
// challenge travels back inside a signed short-lived token, so no server
// state is needed and instances stay interchangeable.
func (h *PasskeyHandler) Challenge(c *gin.Context) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "internal error"}})
		return
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"chal": challenge,
		"use":  challengeUse,
		"iat":  now.Unix(),
		"exp":  now.Add(challengeTTL).Unix(),
	}).SignedString(h.jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "internal error"}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"challenge":       challenge,
		"challenge_token": token,
		"rp_id":           h.rpID(c),
	})
}

func (h *PasskeyHandler) parseChallengeToken(tokenStr string) (string, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		return h.jwtSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	if err != nil {
		return "", err
	}
	if claims["use"] != challengeUse {
		return "", errors.New("wrong token purpose")
	}
	chal, _ := claims["chal"].(string)
	if chal == "" {
		return "", errors.New("missing challenge")
	}
	return chal, nil
}

type passkeyLoginRequest struct {
	ChallengeToken    string `json:"challenge_token" binding:"required"`
	CredentialID      string `json:"credential_id" binding:"required"`
	ClientDataJSON    string `json:"client_data_json" binding:"required"`
	AuthenticatorData string `json:"authenticator_data" binding:"required"`
	Signature         string `json:"signature" binding:"required"`
}

// Login handles POST /auth/passkey/login (public).
func (h *PasskeyHandler) Login(c *gin.Context) {
	var req passkeyLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}
	authFailed := func() {
		c.JSON(http.StatusUnauthorized, gin.H{"error": gin.H{"code": "AUTH_FAILED", "message": "passkey authentication failed"}})
	}

	expectedChallenge, err := h.parseChallengeToken(req.ChallengeToken)
	if err != nil {
		authFailed()
		return
	}

	clientDataRaw, err1 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	authDataRaw, err2 := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	sigRaw, err3 := base64.RawURLEncoding.DecodeString(req.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		authFailed()
		return
	}

	clientData, err := passkey.ParseClientData(clientDataRaw)
	if err != nil || clientData.Type != "webauthn.get" ||
		clientData.Challenge != expectedChallenge ||
		clientData.Origin != h.baseURL(c) {
		authFailed()
		return
	}

	cred, err := h.repo.GetByCredentialID(c.Request.Context(), req.CredentialID)
	if err != nil {
		authFailed()
		return
	}

	authData, err := passkey.ParseAuthData(authDataRaw)
	if err != nil {
		authFailed()
		return
	}
	rpHash := sha256.Sum256([]byte(h.rpID(c)))
	if authData.RPIDHash != rpHash ||
		authData.Flags&passkey.FlagUserPresent == 0 ||
		authData.Flags&passkey.FlagUserVerified == 0 {
		authFailed()
		return
	}

	spki, err := base64.StdEncoding.DecodeString(cred.PublicKey)
	if err != nil {
		authFailed()
		return
	}
	if err := passkey.VerifyAssertion(spki, authDataRaw, clientDataRaw, sigRaw); err != nil {
		authFailed()
		return
	}

	// Synced passkeys legitimately report counter 0 forever; only move ours
	// forward, never reject on it.
	newCount := cred.SignCount
	if int64(authData.SignCount) > newCount {
		newCount = int64(authData.SignCount)
	}
	_ = h.repo.TouchUsed(c.Request.Context(), cred.ID, newCount)

	token, err := service.IssueSessionJWT(h.jwtSecret, cred.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "internal error"}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"token":                 token,
		"prf_salt":              cred.PRFSalt,
		"prf_encrypted_enc_key": cred.PRFEncryptedEncKey,
	})
}

type passkeyRegisterRequest struct {
	Name               string `json:"name"`
	CredentialID       string `json:"credential_id" binding:"required"`
	PublicKey          string `json:"public_key" binding:"required"` // SPKI, base64
	Transports         string `json:"transports"`
	PRFSalt            string `json:"prf_salt"`
	PRFEncryptedEncKey string `json:"prf_encrypted_enc_key"`
}

// Register handles POST /api/auth/passkeys (authenticated). No attestation:
// the session token already proves who is registering, and the public key is
// validated structurally before storage.
func (h *PasskeyHandler) Register(c *gin.Context) {
	var req passkeyRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}
	spki, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": "public_key must be base64"}})
		return
	}
	if _, err := passkey.ParsePublicKey(spki); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": err.Error()}})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 60 {
		name = name[:60]
	}

	p := &models.UserPasskey{
		ID:                 uuid.New(),
		UserID:             middleware.GetUserID(c),
		Name:               name,
		CredentialID:       req.CredentialID,
		PublicKey:          req.PublicKey,
		Transports:         req.Transports,
		PRFSalt:            req.PRFSalt,
		PRFEncryptedEncKey: req.PRFEncryptedEncKey,
	}
	if err := h.repo.Create(c.Request.Context(), p); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": gin.H{"code": "PASSKEY_EXISTS", "message": "could not register passkey"}})
		return
	}
	c.JSON(http.StatusCreated, passkeyView(p))
}

// List handles GET /api/auth/passkeys (authenticated).
func (h *PasskeyHandler) List(c *gin.Context) {
	list, err := h.repo.ListByUser(c.Request.Context(), middleware.GetUserID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "internal error"}})
		return
	}
	out := make([]gin.H, 0, len(list))
	for i := range list {
		out = append(out, passkeyView(&list[i]))
	}
	c.JSON(http.StatusOK, out)
}

// Delete handles DELETE /api/auth/passkeys/:id (authenticated).
func (h *PasskeyHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": "invalid id"}})
		return
	}
	if err := h.repo.Delete(c.Request.Context(), id, middleware.GetUserID(c)); err != nil {
		if errors.Is(err, repository.ErrPasskeyNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": "passkey not found"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "internal error"}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func passkeyView(p *models.UserPasskey) gin.H {
	return gin.H{
		"id":            p.ID,
		"name":          p.Name,
		"credential_id": p.CredentialID,
		"has_prf":       p.PRFEncryptedEncKey != "",
		"created_at":    p.CreatedAt,
		"last_used_at":  p.LastUsedAt,
	}
}
