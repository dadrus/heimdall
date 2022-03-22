package oauth2

import (
	"errors"

	"github.com/dadrus/heimdall/authenticators/config"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Scopes []string

type IntrospectionResponse struct {
	jwt.Claims
	Active    bool   `json:"active"`
	Scopes    Scopes `json:"scope"`
	ClientId  string `json:"client_id"`
	Username  string `json:"username"`
	TokenType string `json:"token_type"`
}

func (ir *IntrospectionResponse) Verify(assertions config.Assertions) error {
	if !ir.Active {
		return errors.New("token is not active")
	}

	return nil
}
