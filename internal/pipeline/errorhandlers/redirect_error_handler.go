package errorhandlers

import (
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	RegisterErrorHandlerTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, ErrorHandler, error) {
			if typ != config.POTRedirect {
				return false, nil, nil
			}

			eh, err := newRedirectErrorHandler(conf)

			return true, eh, err
		})
}

type redirectErrorHandler struct{}

func newRedirectErrorHandler(rawConfig map[string]any) (redirectErrorHandler, error) {
	return redirectErrorHandler{}, nil
}

func (redirectErrorHandler) HandleError(ctx heimdall.Context, err error) error {
	ctx.SetPipelineError(err)

	return err
}

func (redirectErrorHandler) WithConfig(config map[string]any) (ErrorHandler, error) {
	return nil, nil
}
