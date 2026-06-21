package docs

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSwaggerIndexProvidesNativeLogin(t *testing.T) {
	content, err := os.ReadFile("index.html")
	require.NoError(t, err, "read swagger index")

	html := string(content)
	requiredSnippets := []string{
		`id="swagger-login-form"`,
		`/api/auth/login`,
		`data.accessToken`,
		`preauthorizeApiKey("BearerAuth"`,
		`Bearer ${accessToken}`,
	}

	for _, snippet := range requiredSnippets {
		assert.Contains(t, html, snippet)
	}
}
