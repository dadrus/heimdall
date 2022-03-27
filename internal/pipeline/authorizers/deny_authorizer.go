package authorizers

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type denyAuthorizer struct{}

func NewDenyAuthorizer() denyAuthorizer {
	return denyAuthorizer{}
}

func (denyAuthorizer) Authorize(context.Context, *heimdall.SubjectContext) error {
	return &errorsx.ForbiddenError{
		Message: "not authorized",
	}
}

func (denyAuthorizer) WithConfig(config json.RawMessage) (interfaces.Authorizer, error) {
	return nil, nil
}
