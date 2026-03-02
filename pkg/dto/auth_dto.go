package dto

type SignupRequest struct {
	Email               string `json:"email" binding:"required,email"`
	SRPSalt             string `json:"srp_salt" binding:"required"`
	SRPVerifier         string `json:"srp_verifier" binding:"required"`
	PublicKey           string `json:"public_key"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
}

type SignupResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type LoginStep1Request struct {
	Email        string `json:"email" binding:"required,email"`
	ClientPublic string `json:"client_public" binding:"required"`
}

type LoginStep1Response struct {
	SessionID    string `json:"session_id"`
	Salt         string `json:"salt"`
	ServerPublic string `json:"server_public"`
}

type LoginStep2Request struct {
	SessionID   string `json:"session_id" binding:"required"`
	ClientProof string `json:"client_proof" binding:"required"`
}

type LoginStep2Response struct {
	Token               string `json:"token"`
	ServerProof         string `json:"server_proof"`
	EncryptedPrivateKey string `json:"encrypted_private_key,omitempty"`
}
