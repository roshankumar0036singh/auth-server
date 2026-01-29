package utils

// Response structures for consistent API responses

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   *ErrorDetail `json:"error,omitempty"`
}

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
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
