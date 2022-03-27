package authorizers

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type allowAuthorizer struct{}

func NewAllowAuthorizer() allowAuthorizer {
	return allowAuthorizer{}
}

func (allowAuthorizer) Authorize(context.Context, *heimdall.SubjectContext) error {
	return nil
}

func (allowAuthorizer) WithConfig(config json.RawMessage) (interfaces.Authorizer, error) {
	return nil, nil
}
