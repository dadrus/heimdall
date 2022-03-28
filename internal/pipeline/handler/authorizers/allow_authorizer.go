package authorizers

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type allowAuthorizer struct{}

func NewAllowAuthorizer() *allowAuthorizer {
	return &allowAuthorizer{}
}

func (*allowAuthorizer) Authorize(context.Context, *heimdall.SubjectContext) error {
	return nil
}

func (a *allowAuthorizer) WithConfig(config json.RawMessage) (handler.Authorizer, error) {
	return a, nil
}
