package dto

type UpdateMeRequest struct {
	DisplayName string `json:"display_name" binding:"required,min=1,max=100"`
}

type UpdateMeResponse struct {
	DisplayName string `json:"display_name"`
}
