package dto

type CreateItemRequest struct {
	DataEncrypted string `json:"data_encrypted" binding:"required"`
}

type UpdateItemRequest struct {
	DataEncrypted string `json:"data_encrypted" binding:"required"`
	Version       int    `json:"version" binding:"required"`
}
