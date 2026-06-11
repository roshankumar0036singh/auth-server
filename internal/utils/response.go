package utils

import "github.com/gin-gonic/gin"

// Response structures for consistent API responses

type Response struct {
	Success bool         `json:"success"`
	Message string       `json:"message,omitempty"`
	Data    interface{}  `json:"data,omitempty"`
	Error   *ErrorDetail `json:"error,omitempty"`
}

type ErrorDetail struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

const (
	ErrValidation              = "VALIDATION_ERROR"
	ErrUnauthorized            = "UNAUTHORIZED"
	ErrForbidden               = "FORBIDDEN"
	ErrInternalServer          = "INTERNAL_SERVER_ERROR"
	ErrGeneric                 = "ERROR"
	ErrPasswordRestFailed      = "PASSWORD_RESET_FAILED"
	ErrResendFailed            = "RESEND_FAILED"
	ErrVerificationFailed      = "VERIFICATION_FAILED"
	ErrRegistrationFailed      = "REGISTRATION_FAILED"
	ErrMissingToken            = "MISSING_TOKEN"
	ErrProcessFailed           = "PROCESS_FAILED"
	ErrUpdateProfileFailed     = "UPDATE_PROFILE_FAILED"
	ErrPasswordIncorrect       = "INCORRECT_PASSWORD"
	ErrDeleteAccountFailed     = "DELETE_ACCOUNT_FAILED"
	ErrLoginFailed             = "LOGIN_FAILED"
	ErrTokenRefreshFailed      = "TOKEN_REFRESH_FAILED"
	ErrLogoutFailed            = "LOGOUT_FAILED"
	ErrOAuthStateGeneration    = "OAUTH_STATE_GENERATION_FAILED"
	ErrGetAuthURL              = "GET_AUTH_URL_FAILED"
	ErrInvalidState            = "INVALID_STATE"
	ErrTokenExchange           = "TOKEN_EXCHANGE_FAILED"
	ErrFetchUserInfo           = "FETCH_USER_INFO_FAILED"
	ErrMFASetup                = "MFA_SETUP_FAILED"
	ErrMFAVerification         = "MFA_VERIFICATION_FAILED"
	ErrInvalidClientID         = "INVALID_CLIENT_ID"
	ErrInvalidRedirectURI      = "INVALID_REDIRECT_URI"
	ErrMissingRequiredParams   = "MISSING_REQUIRED_PARAMS"
	ErrMissingSessionID        = "MISSING_SESSION_ID"
	ErrRevokeSessionFailed     = "REVOKE_SESSION_FAILED"
	ErrFetchSessionsFailed     = "FETCH_SESSIONS_FAILED"
	ErrUnsupportedResponseType = "UNSUPPORTED_RESPONSE_TYPE"
	ErrSaveConsentFailed       = "SAVE_CONSENT_FAILED"
	ErrAuthCodeGeneration      = "AUTH_CODE_GENERATION_FAILED"
)

// SuccessResponse creates a success response
func SuccessResponse(message string, data interface{}) Response {
	return Response{
		Success: true,
		Message: message,
		Data:    data,
	}
}

// ErrorResponse creates an error response
func ErrorResponse(message string, err error) Response {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	} else {
		errMsg = message
	}

	return Response{
		Success: false,
		Error: &ErrorDetail{
			Code:    ErrGeneric,
			Message: errMsg,
		},
	}
}

// ValidationErrorResponse creates a validation error response
func ValidationErrorResponse(message string) Response {
	return StructuredError(
		ErrValidation,
		message,
		nil,
	)
}

// UnauthorizedResponse returns a 401 Unauthorized response
func UnauthorizedResponse(message string) Response {
	return StructuredError(
		ErrUnauthorized,
		message,
		nil,
	)
}

// ForbiddenResponse returns a 403 Forbidden response
func ForbiddenResponse(message string) Response {
	return StructuredError(
		ErrForbidden,
		message,
		nil,
	)
}

// BadRequestResponse returns a 400 Bad Request response
func BadRequestResponse(c interface{}, message string) {
	// Type assertion to *gin.Context
	if ctx, ok := c.(*gin.Context); ok {
		ctx.JSON(400, Response{
			Success: false,
			Message: message,
		})
	}
}

// InternalServerErrorResponse returns a 500 Internal Server Error response
func InternalServerErrorResponse(c interface{}, message string) {
	// Type assertion to *gin.Context
	if ctx, ok := c.(*gin.Context); ok {
		ctx.JSON(500, Response{
			Success: false,
			Message: message,
		})
	}
}

// For Structured Error Response
func StructuredError(code, message string, details interface{}) Response {
	return Response{
		Success: false,
		Error: &ErrorDetail{
			Code:    code,
			Message: message,
			Details: details,
		},
	}
}
