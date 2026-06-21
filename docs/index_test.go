package docs

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

func readSwaggerIndex(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile("index.html")
	require.NoError(t, err, "read swagger index")
	return string(content)
}

// extractInlineScript returns the body of the page's inline <script> block (the
// one without a src attribute that holds the login logic).
func extractInlineScript(t *testing.T, html string) string {
	t.Helper()
	const open = "<script>"
	start := strings.Index(html, open)
	require.NotEqual(t, -1, start, "inline <script> block not found")
	start += len(open)
	end := strings.Index(html[start:], "</script>")
	require.NotEqual(t, -1, end, "closing </script> not found")
	return html[start : start+end]
}

func TestSwaggerIndexProvidesNativeLogin(t *testing.T) {
	html := readSwaggerIndex(t)

	requiredSnippets := []string{
		`id="swagger-login-form"`,
		`/api/auth/login`,
		`/api/auth/login/mfa`,
		`data.accessToken`,
		`preauthorizeApiKey("BearerAuth"`,
		`Bearer ${accessToken}`,
		`integrity="sha384-`,
	}

	for _, snippet := range requiredSnippets {
		assert.Contains(t, html, snippet)
	}
}

// TestSwaggerIndexInlineScriptParses guards against shipping a broken page: a
// string-only check would pass even with a JavaScript syntax error, so the
// inline script is parsed and any parse error fails the test.
func TestSwaggerIndexInlineScriptParses(t *testing.T) {
	script := extractInlineScript(t, readSwaggerIndex(t))
	require.NotEmpty(t, strings.TrimSpace(script), "inline script should not be empty")

	_, err := js.Parse(parse.NewInputString(script), js.Options{})
	require.NoError(t, err, "inline swagger login script must be valid JavaScript")
}
