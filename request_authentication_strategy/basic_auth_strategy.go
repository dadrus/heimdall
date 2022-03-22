package request_authentication_strategy

import (
	"context"
	"encoding/json"
	"net/http"
)

func NewBasicAuthStrategy(raw json.RawMessage) (*basicAuthStrategy, error) {
	type config struct {
		User     string
		Password string
	}

	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}

	return &basicAuthStrategy{
		user:     c.User,
		password: c.Password,
	}, nil
}

type basicAuthStrategy struct {
	user     string
	password string
}

func (c *basicAuthStrategy) Apply(_ context.Context, req *http.Request) error {
	req.SetBasicAuth(c.user, c.password)
	return nil
}
