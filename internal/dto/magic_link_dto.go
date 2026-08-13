package dto

// MagicLinkRequest is the payload for requesting a passwordless sign-in link (#155).
type MagicLinkRequest struct {
	Email string `json:"email" binding:"required"`
}
