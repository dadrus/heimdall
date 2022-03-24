package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
)

type UnauthorizedAuthenticator struct{}

func (a *UnauthorizedAuthenticator) Authenticate(ctx context.Context, as pipeline.AuthDataSource, sc *heimdall.SubjectContext) error {
	return &errorsx.UnauthorizedError{Message: "denied by authenticator"}
}
