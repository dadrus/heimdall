package endpoint

import (
	"context"
	"net/http"
)

type AuthenticationStrategy interface {
	Apply(context.Context, *http.Request) error
	Hash() []byte
}
