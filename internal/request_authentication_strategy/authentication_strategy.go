package request_authentication_strategy

import (
	"context"
	"net/http"
)

type AuthenticationStrategy interface {
	Apply(context.Context, *http.Request) error
}
