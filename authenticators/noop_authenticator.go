package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/pipeline"
)

type NoopAuthenticator struct{}

func (*NoopAuthenticator) Authenticate(_ context.Context, _ pipeline.AuthDataSource, sc *pipeline.SubjectContext) error {
	sc.Subject = &pipeline.Subject{}
	return nil
}
