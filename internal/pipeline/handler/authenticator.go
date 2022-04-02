package handler

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Authenticator interface {
	Authenticate(context.Context, RequestContext, *heimdall.SubjectContext) error
	WithConfig(config map[string]any) (Authenticator, error)
}
