package errorhandlers

import (
	"context"

	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type jsonErrorHandler struct{}

func NewJsonErrorHandler(rawConfig map[string]any) (jsonErrorHandler, error) {
	return jsonErrorHandler{}, nil
}

func (jsonErrorHandler) HandleError(ctx context.Context, err error) error {
	return nil
}

func (jsonErrorHandler) WithConfig(config map[string]any) (handler.ErrorHandler, error) {
	return nil, nil
}
