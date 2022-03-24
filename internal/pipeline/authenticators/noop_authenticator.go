package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
)

type NoopAuthenticator struct{}

func (*NoopAuthenticator) Authenticate(_ context.Context, _ pipeline.AuthDataSource, sc *heimdall.SubjectContext) error {
	sc.Subject = &heimdall.Subject{}
	return nil
}
