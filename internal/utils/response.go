package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Response structures for consistent API responses

type Response struct {
	Success bool         `json:"success"`
	Message string       `json:"message,omitempty"`
	Data    interface{}  `json:"data,omitempty"`
	Error   *ErrorDetail `json:"error,omitempty"`
}

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"status,omitempty"`
}

// ErrorCodeForStatus maps an HTTP status code to a stable, machine-readable
// error code, so clients can branch on codes instead of parsing messages.
func ErrorCodeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusUnprocessableEntity:
		return "VALIDATION_ERROR"
	case http.StatusTooManyRequests:
		return "RATE_LIMITED"
	case http.StatusInternalServerError:
		return "INTERNAL_ERROR"
	default:
		return "ERROR"
	}
}

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

// WriteError writes a normalized error response with a machine-readable
// code (derived from the HTTP status) and the status itself on the body,
// keeping every handler's error shape identical.
func WriteError(c *gin.Context, status int, message string, err error) {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	} else {
		errMsg = message
	}

	c.JSON(status, Response{
		Success: false,
		Message: message,
		Error: &ErrorDetail{
			Code:    ErrorCodeForStatus(status),
			Message: errMsg,
			Status:  status,
		},
	})
}

// ValidationErrorResponse creates a validation error response
func ValidationErrorResponse(message string) Response {
	return Response{
		Success: false,
		Error: &ErrorDetail{
			Code:    "VALIDATION_ERROR",
			Message: message,
		},
	}
}

// UnauthorizedResponse returns a 401 Unauthorized response
func UnauthorizedResponse(message string) Response {
	return Response{
		Success: false,
		Message: message,
	}
}

// ForbiddenResponse returns a 403 Forbidden response
func ForbiddenResponse(message string) Response {
	return Response{
		Success: false,
		Message: message,
	}
}

// BadRequestResponse returns a 400 Bad Request response
func BadRequestResponse(c *gin.Context, message string) {
	c.JSON(400, Response{
		Success: false,
		Message: message,
	})
}

// InternalServerErrorResponse returns a 500 Internal Server Error response
func InternalServerErrorResponse(c *gin.Context, message string) {
	c.JSON(500, Response{
		Success: false,
		Message: message,
	})
}
