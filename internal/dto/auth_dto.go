package dto

// RegisterRequest represents the registration request payload
type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"firstName" binding:"required"`
	LastName  string `json:"lastName" binding:"required"`
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	AccessToken  string      `json:"accessToken"`
	RefreshToken string      `json:"refreshToken"`
	User         interface{} `json:"user"`
}

// RefreshTokenRequest represents the refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

// TokenRefreshResponse represents the token refresh response
type TokenRefreshResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// LogoutRequest represents the logout request
type LogoutRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// ResendVerificationRequest represents the resend verification request
type ResendVerificationRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ForgotPasswordRequest represents the forgot password request
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest represents the reset password request
type ResetPasswordRequest struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

// SessionResponse represents a user session
type SessionResponse struct {
	ID        string `json:"id"`
	IPAddress string `json:"ipAddress,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
	IsCurrent bool   `json:"isCurrent"`
}
