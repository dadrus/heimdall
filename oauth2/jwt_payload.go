package oauth2

import (
	"gopkg.in/square/go-jose.v2/jwt"
)

type JwtPayload struct {
	jwt.Claims
}

func (jp *JwtPayload) Verify(assertions Assertions) error {
	return nil
}
