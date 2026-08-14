package dto

import "time"

type CreateShareLinkRequest struct {
	// PayloadEncrypted is opaque ciphertext produced by the client. The
	// decryption key only ever lives in the URL fragment client-side.
	PayloadEncrypted string `json:"payload_encrypted" binding:"required"`
	ExpiresInHours   int    `json:"expires_in_hours" binding:"required,min=1,max=72"`
}

type CreateShareLinkResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ShareLinkInfo struct {
	ID         string     `json:"id"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RedeemedAt *time.Time `json:"redeemed_at"`
}

type RedeemShareLinkResponse struct {
	PayloadEncrypted string `json:"payload_encrypted"`
}

type ShareLinkStatusResponse struct {
	Status string `json:"status"` // "available" | "gone"
}
