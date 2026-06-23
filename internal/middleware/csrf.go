package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

const (
	csrfTokenLength  = 32
	csrfCookieName   = "csrf_token"
	csrfHeaderName   = "X-CSRF-Token"
	csrfCookieMaxAge = int(24 * time.Hour / time.Second) // 24 hours
)

// generateCSRFToken generates a cryptographically secure random token.
func generateCSRFToken() (string, error) {
	bytes := make([]byte, csrfTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// SetCSRFTokenHandler issues a CSRF token via a secure cookie.
// Clients must read this cookie and send its value in the X-CSRF-Token header
// on every state-changing request that uses cookie-based authentication.
func SetCSRFTokenHandler(c *gin.Context) {
	token, err := generateCSRFToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			utils.ErrorResponse("Failed to generate CSRF token", err))
		return
	}

	c.SetCookie(
		csrfCookieName,
		token,
		csrfCookieMaxAge,
		"/",
		"",    // domain — empty means current host
		true,  // secure — HTTPS only
		false, // HttpOnly=false intentional: JS must read token to send in X-CSRF-Token header -- NOSONAR
	)

	c.JSON(http.StatusOK, utils.SuccessResponse("CSRF token issued", gin.H{
		"csrf_token": token,
	}))
}

// CSRFMiddleware validates the CSRF token for cookie-based state-changing requests.
// It compares the X-CSRF-Token header against the csrf_token cookie value.
// Safe methods (GET, HEAD, OPTIONS) are always allowed through.
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Safe methods do not require CSRF protection
		method := c.Request.Method
		if method == http.MethodGet ||
			method == http.MethodHead ||
			method == http.MethodOptions {
			c.Next()
			return
		}

		// Only enforce CSRF for cookie-based sessions.
		// Bearer token requests skip this middleware.
		cookieToken, err := c.Cookie(csrfCookieName)
		if err != nil || cookieToken == "" {
			// No cookie present — Bearer token flow, skip
			c.Next()
			return
		}

		headerToken := c.GetHeader(csrfHeaderName)
		if headerToken == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, utils.ForbiddenResponse(
				"Missing X-CSRF-Token header",
			))
			return
		}

		if cookieToken != headerToken {
			c.AbortWithStatusJSON(http.StatusForbidden, utils.ForbiddenResponse(
				"Invalid CSRF token",
			))
			return
		}

		c.Next()
	}
}

// RotateCSRFToken invalidates the current CSRF cookie by issuing a new one.
// Call this after login and logout.
func RotateCSRFToken(c *gin.Context) {
	token, err := generateCSRFToken()
	if err != nil {
		return
	}
	c.SetCookie(csrfCookieName, token, csrfCookieMaxAge, "/", "", true, false) // HttpOnly=false intentional: JS must read token to send in X-CSRF-Token header -- NOSONAR
}