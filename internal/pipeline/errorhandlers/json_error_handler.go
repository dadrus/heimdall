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
			if typ != config.POTJson {
				return false, nil, nil
			}

			eh, err := newJSONErrorHandler(conf)

			return true, eh, err
		})
}

type jsonErrorHandler struct{}

func newJSONErrorHandler(rawConfig map[string]any) (jsonErrorHandler, error) {
	return jsonErrorHandler{}, nil
}

func (jsonErrorHandler) HandleError(ctx heimdall.Context, err error) error {
	ctx.SetPipelineError(err)

	return nil
}

func (jsonErrorHandler) WithConfig(config map[string]any) (ErrorHandler, error) {
	return nil, nil
}
