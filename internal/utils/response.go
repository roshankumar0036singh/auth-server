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
	ErrValidation     = "VALIDATION_ERROR"
	ErrUnauthorized   = "UNAUTHORIZED"
	ErrForbidden      = "FORBIDDEN"
	ErrInternalServer = "INTERNAL_SERVER_ERROR"
	ErrGeneric        = "ERROR"
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
			Code:    "ERROR",
			Message: errMsg,
		},
	}
}

// ValidationErrorResponse creates a validation error response
func ValidationErrorResponse(message string) Response {
	return StructuredError(
		ErrValidation,
		"Invalid request",
		message,
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
