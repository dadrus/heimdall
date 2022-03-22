package request_authentication_strategy

import (
	"context"
	"net/http"
)

func NewNoopStrategy() (*noopAuthStrategy, error) {
	return &noopAuthStrategy{}, nil
}

type noopAuthStrategy struct{}

func (c *noopAuthStrategy) Apply(_ context.Context, _ *http.Request) error {
	return nil
}
