package authorizers

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
)

type allowAuthorizer struct{}

func NewAllowAuthorizer() *allowAuthorizer {
	return &allowAuthorizer{}
}

func (*allowAuthorizer) Authorize(ctx heimdall.Context, sub *subject.Subject) error {
	return nil
}

func (a *allowAuthorizer) WithConfig(map[string]any) (handler.Authorizer, error) {
	return a, nil
}
