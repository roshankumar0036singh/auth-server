package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/service"
)

// wellKnownHandler serves /.well-known/jwks.json (issue #171).
type wellKnownHandler struct {
	jwks *service.JWKSService
}

// NewWellKnownHandler builds the well-known endpoint handler.
func NewWellKnownHandler(jwks *service.JWKSService) *wellKnownHandler {
	return &wellKnownHandler{jwks: jwks}
}

// JWKS returns the RSA public key document so resource servers can verify
// JWT signatures autonomously.
// @Summary JSON Web Key Set
// @Description Publishes the active public key (RS256) for JWT verification. Empty key set when HS256-only mode is configured.
// @Tags well-known
// @Produce json
// @Success 200 {object} service.JWKSResponse
// @Router /.well-known/jwks.json [get]
func (h *wellKnownHandler) JWKS(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, h.jwks.Document())
}
