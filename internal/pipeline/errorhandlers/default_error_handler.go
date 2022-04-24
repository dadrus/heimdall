package errorhandlers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerErrorHandlerTypeFactory(
		func(_ string, typ config.PipelineObjectType, conf map[any]any) (bool, ErrorHandler, error) {
			if typ != config.POTDefault {
				return false, nil, nil
			}

			eh, err := newDefaultErrorHandler(conf)

			return true, eh, err
		})
}

type defaultErrorHandler struct{}

func newDefaultErrorHandler(rawConfig map[any]any) (*defaultErrorHandler, error) {
	return &defaultErrorHandler{}, nil
}

func (eh *defaultErrorHandler) Execute(ctx heimdall.Context, err error) (bool, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Handling error using default error handler")

	ctx.SetPipelineError(err)

	return true, nil
}

func (eh *defaultErrorHandler) WithConfig(config map[any]any) (ErrorHandler, error) {
	return eh, nil
}
