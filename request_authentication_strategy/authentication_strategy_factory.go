package request_authentication_strategy

import (
	"encoding/json"
	"fmt"
)

func NewAuthenticationStrategy(name string, c json.RawMessage) (as AuthenticationStrategy, err error) {
	switch name {
	case "":
		return NewNoopStrategy()
	case "basic":
		return NewBasicAuthStrategy(c)
	case "api_key":
		return NewApiKeyStrategy(c)
	case "client_credentials":
		return NewClientCredentialsStrategy(c)
	default:
		return nil, fmt.Errorf("unsupported authentication type: %s", name)
	}
}
