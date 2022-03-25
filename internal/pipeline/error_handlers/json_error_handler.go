package error_handlers

import (
	"context"
	"encoding/json"
)

type jsonErrorHandler struct{}

func NewJsonErrorHandlerFromJSON(rawConfig json.RawMessage) (jsonErrorHandler, error) {
	return jsonErrorHandler{}, nil
}

func (jsonErrorHandler) HandleError(ctx context.Context, err error) error {
	return nil
}
