package oauth2

import (
	"github.com/dadrus/heimdall/authenticators/config"
	"gopkg.in/square/go-jose.v2/jwt"
)

type JwtPayload struct {
	jwt.Claims
}

func (jp *JwtPayload) Verify(assertions config.Assertions) error {
	return nil
}
