package request_authentication_strategy

import (
	"context"
	"encoding/json"
	"net/http"
)

func NewApiKeyStrategy(raw json.RawMessage) (AuthenticationStrategy, error) {
	type config struct {
		In    string
		Name  string
		Value string
	}

	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}

	return &apiKeyStrategy{
		in:    c.In,
		name:  c.Name,
		value: c.Value,
	}, nil
}

type apiKeyStrategy struct {
	name  string
	value string
	in    string
}

func (c *apiKeyStrategy) Apply(_ context.Context, req *http.Request) error {
	switch c.in {
	case "cookie":
		req.AddCookie(&http.Cookie{Name: c.name, Value: c.value})
	default:
		req.Header.Set(c.name, c.value)
	}
	return nil
}
