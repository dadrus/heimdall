package authorizers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthorizerTypeFactory(
		func(_ string, typ config.PipelineHandlerType, conf map[string]any) (bool, Authorizer, error) {
			if typ != config.POTAllow {
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
