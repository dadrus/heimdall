package errorhandlers

import (
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerErrorHandlerTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, ErrorHandler, error) {
			if typ != config.POTDefault {
				return false, nil, nil
			}

			eh, err := newDefaultErrorHandler(conf)

			return true, eh, err
		})
}

type defaultErrorHandler struct{}

func newDefaultErrorHandler(rawConfig map[string]any) (*defaultErrorHandler, error) {
	return &defaultErrorHandler{}, nil
}

func (eh *defaultErrorHandler) HandleError(ctx heimdall.Context, err error) (bool, error) {
	ctx.SetPipelineError(err)

	return true, nil
}

func (eh *defaultErrorHandler) WithConfig(config map[string]any) (ErrorHandler, error) {
	return eh, nil
}
