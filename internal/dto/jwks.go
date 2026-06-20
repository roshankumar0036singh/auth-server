package dto

// JWK represents a single JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key Type
	Alg string `json:"alg"` // Algorithm
	Use string `json:"use"` // Public Key Use (e.g., "sig")
	Kid string `json:"kid"` // Key ID
	N   string `json:"n"`   // Modulus (Base64url encoded)
	E   string `json:"e"`   // Exponent (Base64url encoded)
}

// JWKSResponse represents a JSON Web Key Set
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}
