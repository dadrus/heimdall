package authorizers

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type allowAuthorizer struct{}

func NewAllowAuthorizer() allowAuthorizer {
	return allowAuthorizer{}
}

func (allowAuthorizer) Authorize(context.Context, *heimdall.SubjectContext) error {
	return nil
}
