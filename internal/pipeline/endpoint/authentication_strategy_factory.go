package endpoint

import (
	"encoding/json"
	"fmt"
)

func NewAuthenticationStrategy(name string, c json.RawMessage) (AuthenticationStrategy, error) {
	switch name {
	case "":
		return &NoopAuthStrategy{}, nil
	case "basic":
		var s BasicAuthStrategy
		err := json.Unmarshal(c, &s)
		return &s, err
	case "api_key":
		var s ApiKeyStrategy
		err := json.Unmarshal(c, &s)
		return &s, err
	case "client_credentials":
		var s ClientCredentialsStrategy
		err := json.Unmarshal(c, &s)
		return &s, err
	default:
		return nil, fmt.Errorf("unsupported authentication type: %s", name)
	}
}
