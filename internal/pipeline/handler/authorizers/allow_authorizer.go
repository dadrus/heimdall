package authorizers

import (
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	handler.RegisterAuthorizerTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, handler.Authorizer, error) {
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

func (*allowAuthorizer) Authorize(ctx heimdall.Context, sub *subject.Subject) error {
	return nil
}

func (a *allowAuthorizer) WithConfig(map[string]any) (handler.Authorizer, error) {
	return a, nil
}
