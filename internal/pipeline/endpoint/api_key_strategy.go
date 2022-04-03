package endpoint

import (
	"context"
	"net/http"
)

type APIKeyStrategy struct {
	In    string `mapstructure:"in"`
	Name  string `mapstructure:"name"`
	Value string `mapstructure:"value"`
}

func (c *APIKeyStrategy) Apply(_ context.Context, req *http.Request) error {
	switch c.In {
	case "cookie":
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	case "header":
		req.Header.Set(c.Name, c.Value)
	}

	return nil
}
