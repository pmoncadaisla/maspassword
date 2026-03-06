package dto

type CreateTeamRequest struct {
	Name string `json:"name" binding:"required"`
}

type AddMemberRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type UpdateMemberRoleRequest struct {
	Role string `json:"role" binding:"required,oneof=admin member"`
}

type PendingVaultKeyInfo struct {
	UserID    string `json:"user_id"`
	VaultID   string `json:"vault_id"`
	PublicKey string `json:"public_key"`
}
