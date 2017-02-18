package fireauth

import "gopkg.in/jose.v1/jwt"

// TokenVerifier verifies authenticaion tokens
type TokenVerifier interface {
	Verify(token string) (userID string, claims jwt.Claims, err error)
}
