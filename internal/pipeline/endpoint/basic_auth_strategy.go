package endpoint

import (
	"context"
	"net/http"
)

type BasicAuthStrategy struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

func (c *BasicAuthStrategy) Apply(_ context.Context, req *http.Request) error {
	req.SetBasicAuth(c.User, c.Password)

	return nil
}
