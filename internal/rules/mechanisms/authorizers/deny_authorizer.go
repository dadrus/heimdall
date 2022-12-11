package authorizers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthorizerTypeFactory(
		func(id string, typ string, _ map[string]any) (bool, Authorizer, error) {
			if typ != AuthorizerDeny {
				return false, nil, nil
			}

			return true, newDenyAuthorizer(id), nil
		})
}

type denyAuthorizer struct {
	id string
}

func newDenyAuthorizer(id string) *denyAuthorizer {
	return &denyAuthorizer{id: id}
}

func (a *denyAuthorizer) Execute(ctx heimdall.Context, _ *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authorizing using deny authorizer")

	return errorchain.
		NewWithMessage(heimdall.ErrAuthorization, "denied by authorizer").
		WithErrorContext(a)
}

func (a *denyAuthorizer) WithConfig(map[string]any) (Authorizer, error) {
	return a, nil
}

func (a *denyAuthorizer) HandlerID() string {
	return a.id
}
