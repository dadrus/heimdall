package errorhandlers

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type jsonErrorHandler struct{}

func NewJsonErrorHandler(rawConfig map[string]any) (jsonErrorHandler, error) {
	return jsonErrorHandler{}, nil
}

func (jsonErrorHandler) HandleError(ctx heimdall.Context, err error) error {
	ctx.SetPipelineError(err)
	return nil
}

func (jsonErrorHandler) WithConfig(config map[string]any) (handler.ErrorHandler, error) {
	return nil, nil
}
