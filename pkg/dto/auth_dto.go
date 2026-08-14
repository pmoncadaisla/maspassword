package dto

type SignupRequest struct {
	Email                       string `json:"email" binding:"required,email"`
	SRPSalt                     string `json:"srp_salt" binding:"required"`
	SRPVerifier                 string `json:"srp_verifier" binding:"required"`
	PublicKey                   string `json:"public_key"`
	EncryptedPrivateKey         string `json:"encrypted_private_key"`
	RecoveryEncryptedPrivateKey string `json:"recovery_encrypted_private_key"`
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

type SessionInfoResponse struct {
	UserID              string `json:"user_id"`
	Email               string `json:"email"`
	DisplayName         string `json:"display_name"`
	AuthMethod          string `json:"auth_method"`
	EncryptionSetup     bool   `json:"encryption_setup"`
	EncryptedPrivateKey string `json:"encrypted_private_key,omitempty"`
	SRPSalt             string `json:"srp_salt,omitempty"`
	Token               string `json:"token"`
	IsAdmin             bool   `json:"is_admin"`
}

type SetupEncryptionRequest struct {
	SRPSalt                     string `json:"srp_salt" binding:"required"`
	SRPVerifier                 string `json:"srp_verifier" binding:"required"`
	PublicKey                   string `json:"public_key" binding:"required"`
	EncryptedPrivateKey         string `json:"encrypted_private_key" binding:"required"`
	RecoveryEncryptedPrivateKey string `json:"recovery_encrypted_private_key"`
}

type RecoveryDataResponse struct {
	RecoveryEncryptedPrivateKey string `json:"recovery_encrypted_private_key"`
	PublicKey                   string `json:"public_key"`
}

// RecoverChallengeRequest starts the recovery proof-of-possession handshake.
type RecoverChallengeRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// RecoverChallengeResponse carries a nonce encrypted to the account's stored
// public key. Only a caller who can decrypt it (i.e. who holds the recovery key
// and thus recovered the private key) can complete the recovery.
type RecoverChallengeResponse struct {
	ChallengeID    string `json:"challenge_id"`
	EncryptedNonce string `json:"encrypted_nonce"`
}

type RecoverRequest struct {
	Email                       string `json:"email" binding:"required,email"`
	ChallengeID                 string `json:"challenge_id" binding:"required"`
	Nonce                       string `json:"nonce" binding:"required"`
	SRPSalt                     string `json:"srp_salt" binding:"required"`
	SRPVerifier                 string `json:"srp_verifier" binding:"required"`
	EncryptedPrivateKey         string `json:"encrypted_private_key" binding:"required"`
	RecoveryEncryptedPrivateKey string `json:"recovery_encrypted_private_key" binding:"required"`
}
