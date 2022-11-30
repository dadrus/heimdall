package errorhandlers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerErrorHandlerTypeFactory(
		func(_ string, typ string, conf map[string]any) (bool, ErrorHandler, error) {
			if typ != ErrorHandlerDefault {
				return false, nil, nil
			}

			eh, err := newDefaultErrorHandler()

			return true, eh, err
		})
}

type defaultErrorHandler struct{}

func newDefaultErrorHandler() (*defaultErrorHandler, error) {
	return &defaultErrorHandler{}, nil
}

func (eh *defaultErrorHandler) Execute(ctx heimdall.Context, err error) (bool, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Handling error using default error handler")

	ctx.SetPipelineError(err)

	return true, nil
}

func (eh *defaultErrorHandler) WithConfig(_ map[string]any) (ErrorHandler, error) {
	return eh, nil
}
