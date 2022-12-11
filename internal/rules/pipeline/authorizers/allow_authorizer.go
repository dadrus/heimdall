package authorizers

import (
	"github.com/dadrus/heimdall/internal/rules/pipeline/subject"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthorizerTypeFactory(
		func(_ string, typ string, conf map[string]any) (bool, Authorizer, error) {
			if typ != AuthorizerAllow {
				return false, nil, nil
			}

			return true, newAllowAuthorizer(), nil
		})
}

type allowAuthorizer struct{}

func newAllowAuthorizer() *allowAuthorizer {
	return &allowAuthorizer{}
}

func (*allowAuthorizer) Execute(ctx heimdall.Context, _ *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authorizing using allow authorizer")

	return nil
}

func (a *allowAuthorizer) WithConfig(map[string]any) (Authorizer, error) {
	return a, nil
}
