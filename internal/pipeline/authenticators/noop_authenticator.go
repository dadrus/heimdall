package authenticators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type noopAuthenticator struct{}

func NewNoopAuthenticator() *noopAuthenticator {
	return &noopAuthenticator{}
}

func (*noopAuthenticator) Authenticate(_ context.Context, _ interfaces.AuthDataSource, sc *heimdall.SubjectContext) error {
	sc.Subject = &heimdall.Subject{}
	return nil
}

func (a *noopAuthenticator) WithConfig(_ json.RawMessage) (pipeline.Authenticator, error) {
	// nothing can be reconfigured
	return a, nil
}
