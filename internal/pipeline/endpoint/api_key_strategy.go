package endpoint

import (
	"context"
	"net/http"
)

type APIKeyStrategy struct {
	In    string `yaml:"in"`
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
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
