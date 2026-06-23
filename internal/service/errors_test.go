package service_test

import (
	"testing"

	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/stretchr/testify/assert"
)

func TestServiceErrors_MappingAndFormatting(t *testing.T) {
	t.Run("Verify ErrUserNotFound is bound correctly to repository layer", func(t *testing.T) {
		// Ensure that the service layer error maps to the repository level error
		assert.ErrorIs(t, service.ErrUserNotFound, repository.ErrUserNotFound)
	})

	t.Run("Verify ErrTemplateNotFound formatting string implementation", func(t *testing.T) {
		err := &service.ErrTemplateNotFound{Name: "welcome_onboarding.html"}
		
		expectedMessage := `email template "welcome_onboarding.html" not found`
		assert.Equal(t, expectedMessage, err.Error())
	})
}