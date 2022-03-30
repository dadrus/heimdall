package oauth2

import "errors"

type IntrospectionResponse struct {
	Claims

	Active    bool   `json:"active,omitempty"`
	ClientId  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

func (c IntrospectionResponse) Validate(a Expectation) error {
	if !c.Active {
		return errors.New("token is not active")
	}

	return c.Claims.Validate(a)
}
