package docs

import (
	"os"
	"strings"
	"testing"
)

func TestSwaggerIndexProvidesNativeLogin(t *testing.T) {
	content, err := os.ReadFile("index.html")
	if err != nil {
		t.Fatalf("read swagger index: %v", err)
	}

	html := string(content)
	requiredSnippets := []string{
		`id="swagger-login-form"`,
		`/api/auth/login`,
		`data.accessToken`,
		`preauthorizeApiKey("BearerAuth"`,
		`Bearer ${accessToken}`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(html, snippet) {
			t.Fatalf("expected swagger index to contain %q", snippet)
		}
	}
}
