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
	AccessToken  string      `json:"accessToken,omitempty"`
	RefreshToken string      `json:"refreshToken,omitempty"`
	User         interface{} `json:"user,omitempty"`
	// MFARequired is true when the password step succeeded but an MFA code is
	// still required. In that case AccessToken/RefreshToken are empty and
	// MFAToken must be presented to /login/mfa to complete authentication.
	MFARequired bool   `json:"mfaRequired,omitempty"`
	MFAToken    string `json:"mfaToken,omitempty"`
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

// UpdateProfileRequest represents profile update data
type UpdateProfileRequest struct {
	FirstName string `json:"firstName" binding:"max=100"`
	LastName  string `json:"lastName" binding:"max=100"`
	Phone     string `json:"phone" binding:"max=20"`
}

// ChangePasswordRequest represents password change data
type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword" binding:"required"`
	NewPassword     string `json:"newPassword" binding:"required,min=8"`
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

// MFAEnableResponse represents the response when enabling MFA
type MFAEnableResponse struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qrCodeUrl"`
	BackupCodes []string `json:"backupCodes,omitempty"`
}

// MFAVerifyRequest represents the request to verify/enable MFA
type MFAVerifyRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

// MFADisableRequest represents the request to disable MFA
type MFADisableRequest struct {
	// Password re-authenticates the user for this sensitive operation
	Password string `json:"password" binding:"required"`
	Code     string `json:"code" binding:"required,len=6"`
}

// MFALoginRequest represents the request to login with MFA. The MFAToken is
// the short-lived token returned by the password step (proving the password
// was verified); the email is no longer accepted here to prevent bypassing
// the password step.
type MFALoginRequest struct {
	MFAToken string `json:"mfaToken" binding:"required"`
	Code     string `json:"code" binding:"required,len=6"`
	BackupCode string `json:"backupCode,omitempty"`
}

// LoginResponse represents the login response (updated for MFA)
// If MFA is required but not provided, this will be returned with MFAEnabled=true and no tokens
