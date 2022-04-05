package errorhandlers

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type redirectErrorHandler struct{}

func NewRedirectErrorHandler(rawConfig map[string]any) (redirectErrorHandler, error) {
	return redirectErrorHandler{}, nil
}

func (redirectErrorHandler) HandleError(ctx heimdall.Context, err error) error {
	ctx.SetPipelineError(err)
	return err
}

func (redirectErrorHandler) WithConfig(config map[string]any) (handler.ErrorHandler, error) {
	return nil, nil
}
