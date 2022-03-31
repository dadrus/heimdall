package oauth2

import "errors"

var ErrTokenNotActive = errors.New("token is not active")

type IntrospectionResponse struct {
	Claims

	Active    bool   `json:"active,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

func (c IntrospectionResponse) Validate(a Expectation) error {
	if !c.Active {
		return ErrTokenNotActive
	}

	return c.Claims.Validate(a)
}
