package dto

import "time"

// CreateDeviceRequest is the body of POST /api/devices. Only the display
// name travels to the server — never any key material (zero-knowledge).
type CreateDeviceRequest struct {
	Name string `json:"name" binding:"required"`
}

// CreateDeviceResponse returns the plaintext device token exactly once.
// Only its SHA-256 hash is stored server-side.
type CreateDeviceResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
}

// DeviceResponse is one linked device in GET /api/devices (no token, no hash).
type DeviceResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}
