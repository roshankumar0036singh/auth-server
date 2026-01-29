package service_test

import (
	"testing"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func TestAuthService_Register_Integration(t *testing.T) {
	service, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	req := &dto.RegisterRequest{
		Email:     "newuser@example.com",
		Password:  "Password123!",
		FirstName: "John",
		LastName:  "Doe",
	}

	user, err := service.Register(req)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, req.Email, user.Email)
	assert.False(t, user.EmailVerified)
}

func TestAuthService_Login_Integration(t *testing.T) {
	service, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	// Setup: Create user via Register to ensure hashing
	req := &dto.RegisterRequest{
		Email:     "login@example.com",
		Password:  "Password123!",
		FirstName: "Login",
		LastName:  "User",
	}
	_, err := service.Register(req)
	assert.NoError(t, err)

	// Test Login Success
	loginReq := &dto.LoginRequest{
		Email:    "login@example.com",
		Password: "Password123!",
	}
	resp, err := service.Login(loginReq, "127.0.0.1", "UserAgent")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)

	// Test Login Fail
	loginReqFail := &dto.LoginRequest{
		Email:    "login@example.com",
		Password: "WrongPassword!",
	}
	_, err = service.Login(loginReqFail, "127.0.0.1", "UserAgent")
	assert.Error(t, err)
}
