package request_authentication_strategy

import (
	"context"
	"net/http"
)

type NoopAuthStrategy struct{}

func (c *NoopAuthStrategy) Apply(_ context.Context, _ *http.Request) error {
	return nil
}
