package dto

// GlobalSettingsResponse is the payload of GET/PUT /api/admin/settings.
type GlobalSettingsResponse struct {
	DefaultTheme string `json:"default_theme"`
}

// UpdateGlobalSettingsRequest is the body of PUT /api/admin/settings.
type UpdateGlobalSettingsRequest struct {
	DefaultTheme string `json:"default_theme" binding:"required"`
}
