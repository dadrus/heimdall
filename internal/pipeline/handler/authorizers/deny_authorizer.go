package authorizers

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type denyAuthorizer struct{}

func NewDenyAuthorizer() *denyAuthorizer {
	return &denyAuthorizer{}
}

func (*denyAuthorizer) Authorize(ctx heimdall.Context, sub *subject.Subject) error {
	return errorchain.NewWithMessage(heimdall.ErrAuthorization, "denied by authorizer")
}

func (a *denyAuthorizer) WithConfig(map[string]any) (handler.Authorizer, error) {
	return a, nil
}
