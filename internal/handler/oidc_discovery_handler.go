package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
)

type OIDCDiscoveryHandler struct {
	cfg *config.Config
}

func NewOIDCDiscoveryHandler(cfg *config.Config) *OIDCDiscoveryHandler {
	return &OIDCDiscoveryHandler{cfg: cfg}
}

// GetConfiguration returns the OpenID Connect discovery document
// @Summary Get OpenID Connect Configuration
// @Description Returns the OpenID Connect discovery metadata document
// @Tags OpenID Connect
// @Produce json
// @Success 200 {object} dto.OIDCDiscoveryResponse
// @Router /.well-known/openid-configuration [get]
func (h *OIDCDiscoveryHandler) GetConfiguration(c *gin.Context) {
	baseURL := strings.TrimRight(h.cfg.App.URL, "/")

	response := dto.OIDCDiscoveryResponse{
		Issuer:                baseURL,
		AuthorizationEndpoint: fmt.Sprintf("%s/oauth/authorize", baseURL),
		TokenEndpoint:         fmt.Sprintf("%s/oauth/token", baseURL),
		UserinfoEndpoint:      fmt.Sprintf("%s/oauth/userinfo", baseURL),
		JwksURI:               fmt.Sprintf("%s/.well-known/jwks.json", baseURL),
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
		},
		ResponseTypesSupported: []string{
			"code",
		},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
		},
		SubjectTypesSupported: []string{
			"public",
		},
		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
	}

	c.JSON(http.StatusOK, response)
}
