package handler

import (
	"encoding/base64"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
)

type JWKSHandler struct {
	cfg *config.Config
}

func NewJWKSHandler(cfg *config.Config) *JWKSHandler {
	return &JWKSHandler{cfg: cfg}
}

// GetJWKS returns the public keys in JWKS format
// @Summary Get JSON Web Key Set
// @Description Returns the public keys used to verify JWTs issued by this server
// @Tags OpenID Connect
// @Produce json
// @Success 200 {object} dto.JWKSResponse
// @Router /.well-known/jwks.json [get]
func (h *JWKSHandler) GetJWKS(c *gin.Context) {
	pubKey := h.cfg.JWT.PublicKey

	if pubKey == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "public key not configured", "code": "INTERNAL_SERVER_ERROR"})
		return
	}

	// The modulus N needs to be BigEndian bytes, encoded as Base64Url (without padding)
	nBytes := pubKey.N.Bytes()
	nStr := base64.RawURLEncoding.EncodeToString(nBytes)

	// Exponent E is an int, need to encode to bytes then Base64Url
	eBytes := big.NewInt(int64(pubKey.E)).Bytes()
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)

	jwk := dto.JWK{
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		Kid: h.cfg.JWT.KeyID,
		N:   nStr,
		E:   eStr,
	}

	c.JSON(http.StatusOK, dto.JWKSResponse{
		Keys: []dto.JWK{jwk},
	})
}
