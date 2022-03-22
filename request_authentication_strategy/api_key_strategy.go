package request_authentication_strategy

import (
	"context"
	"net/http"
)

type ApiKeyStrategy struct {
	In    string `json:"in"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (c *ApiKeyStrategy) Apply(_ context.Context, req *http.Request) error {
	switch c.In {
	case "cookie":
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	case "header":
		req.Header.Set(c.Name, c.Value)
	}
	return nil
}
