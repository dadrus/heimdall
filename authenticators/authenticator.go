package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/pipeline"
)

type Authenticator interface {
	Authenticate(context.Context, pipeline.AuthDataSource, *pipeline.SubjectContext) error
}
