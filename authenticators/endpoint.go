package authenticators

import (
	"context"
	"io"
)

type Endpoint interface {
	SendRequest(ctx context.Context, body io.Reader) ([]byte, error)
}
