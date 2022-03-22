package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/pipeline"
)

type Authenticator interface {
	Id() string
	Authenticate(context.Context, pipeline.AuthDataSource, *pipeline.SubjectContext) error
}
