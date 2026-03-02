package dto

type CreateTeamRequest struct {
	Name string `json:"name" binding:"required"`
}

type AddMemberRequest struct {
	Email string `json:"email" binding:"required,email"`
}
