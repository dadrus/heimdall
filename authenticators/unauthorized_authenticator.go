package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/errorsx"
	"github.com/dadrus/heimdall/pipeline"
)

type UnauthorizedAuthenticator struct{}

func (a *UnauthorizedAuthenticator) Authenticate(ctx context.Context, as pipeline.AuthDataSource, sc *pipeline.SubjectContext) error {
	return &errorsx.UnauthorizedError{Message: "denied by authenticator"}
}
