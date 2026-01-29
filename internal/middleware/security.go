package middleware

import (
	"github.com/gin-contrib/secure"
	"github.com/gin-gonic/gin"
)

// SecurityMiddleware returns a middleware that sets security headers
func SecurityMiddleware() gin.HandlerFunc {
	return secure.New(secure.Config{
		STSSeconds:            315360000, // 10 years
		STSIncludeSubdomains:  true,
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data: https:;",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	})
}
