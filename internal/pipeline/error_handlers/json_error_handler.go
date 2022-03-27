package error_handlers

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type jsonErrorHandler struct{}

func NewJsonErrorHandlerFromJSON(rawConfig json.RawMessage) (jsonErrorHandler, error) {
	return jsonErrorHandler{}, nil
}

func (jsonErrorHandler) HandleError(ctx context.Context, err error) error {
	return nil
}

func (jsonErrorHandler) WithConfig(config json.RawMessage) (interfaces.ErrorHandler, error) {
	return nil, nil
}
