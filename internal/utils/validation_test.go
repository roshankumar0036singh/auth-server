package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "password too short",
			password:    "Ab1!",
			expectError: true,
			errorMsg:    "password must be at least 8 characters long",
		},
		{
			name:        "missing uppercase",
			password:    "password1!",
			expectError: true,
			errorMsg:    "password must contain at least one uppercase letter",
		},
		{
			name:        "missing lowercase",
			password:    "PASSWORD1!",
			expectError: true,
			errorMsg:    "password must contain at least one lowercase letter",
		},
		{
			name:        "missing number",
			password:    "Password!",
			expectError: true,
			errorMsg:    "password must contain at least one number",
		},
		{
			name:        "missing special character",
			password:    "Password1",
			expectError: true,
			errorMsg:    "password must contain at least one special character",
		},
		{
			name:        "valid password",
			password:    "Password1!",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, tt.errorMsg, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}