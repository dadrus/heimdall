package authorizers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthorizerTypeFactory(
		func(_ string, typ config.PipelineObjectType, conf map[string]any) (bool, Authorizer, error) {
			if typ != config.POTDeny {
				return false, nil, nil
			}

			return true, newDenyAuthorizer(), nil
		})
}

type denyAuthorizer struct{}

func newDenyAuthorizer() *denyAuthorizer {
	return &denyAuthorizer{}
}

func (*denyAuthorizer) Execute(ctx heimdall.Context, _ *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authorizing using deny authorizer")

	return errorchain.NewWithMessage(heimdall.ErrAuthorization, "denied by authorizer")
}

func (a *denyAuthorizer) WithConfig(map[string]any) (Authorizer, error) {
	return a, nil
}
