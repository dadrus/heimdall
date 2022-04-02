package errorhandlers

import (
	"context"

	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type redirectErrorHandler struct{}

func NewRedirectErrorHandler(rawConfig map[string]any) (redirectErrorHandler, error) {
	return redirectErrorHandler{}, nil
}

func (redirectErrorHandler) HandleError(ctx context.Context, err error) error {
	return nil
}

func (redirectErrorHandler) WithConfig(config map[string]any) (handler.ErrorHandler, error) {
	return nil, nil
}
