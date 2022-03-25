package error_handlers

import (
	"context"
	"encoding/json"
)

type redirectErrorHandler struct{}

func NewRedirectErrorHandlerFromJSON(rawConfig json.RawMessage) (redirectErrorHandler, error) {
	return redirectErrorHandler{}, nil
}

func (redirectErrorHandler) HandleError(ctx context.Context, err error) error {
	return nil
}
