package service_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

func TestAuditService_GetUserAuditLogs(t *testing.T) {
	tests := []struct {
		name          string
		page          int
		limit         int
		expectedPage  int
		expectedCount int64
		expectedMore  bool
		expectedLogs  int
		createLogs    int
	}{
		{
			name:          "should return first page audit logs",
			page:          1,
			limit:         10,
			expectedPage:  1,
			expectedCount: 1,
			expectedMore:  false,
			expectedLogs:  1,
			createLogs:    0,
		},
		{
			name:          "should return empty logs for second page",
			page:          2,
			limit:         10,
			expectedPage:  2,
			expectedCount: 1,
			expectedMore:  false,
			expectedLogs:  0,
			createLogs:    0,
		},
		{
			name:          "should indicate more pages available",
			page:          1,
			limit:         1,
			expectedPage:  1,
			expectedCount: 2,
			expectedMore:  true,
			expectedLogs:  1,
			createLogs:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService, db, mr := testutils.SetupIntegrationTest(t)

			t.Cleanup(func() {
				mr.Close()
			})

			auditRepo := repository.NewAuditRepository(db)
			auditService := service.NewAuditService(auditRepo)

			user, err := authService.Register(&dto.RegisterRequest{
				Email:     strings.ReplaceAll(tt.name, " ", "_") + "@example.com",
				Password:  "Password123!",
				FirstName: "Audit",
				LastName:  "Test",
			})

			assert.NoError(t, err)

			for i := 0; i < tt.createLogs; i++ {
				time.Sleep(10 * time.Millisecond)

				_, err := authService.Login(
					&dto.LoginRequest{
						Email:    strings.ReplaceAll(tt.name, " ", "_") + "@example.com",
						Password: "Password123!",
					},
					"127.0.0.1",
					"test-agent",
				)

				assert.NoError(t, err)
			}

			response, err := auditService.GetUserAuditLogs(
				user.ID,
				tt.page,
				tt.limit,
			)

			assert.NoError(t, err)
			assert.NotNil(t, response)

			assert.Equal(
				t,
				tt.expectedPage,
				response.MetaData.CurrentPage,
			)

			assert.Equal(
				t,
				tt.expectedCount,
				response.MetaData.TotalCount,
			)

			assert.Equal(
				t,
				tt.expectedMore,
				response.MetaData.HasMore,
			)

			assert.Len(
				t,
				response.Logs,
				tt.expectedLogs,
			)
		})
	}
}
