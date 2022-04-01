package errorhandlers

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type redirectErrorHandler struct{}

func NewRedirectErrorHandlerFromJSON(rawConfig json.RawMessage) (redirectErrorHandler, error) {
	return redirectErrorHandler{}, nil
}

func (redirectErrorHandler) HandleError(ctx context.Context, err error) error {
	return nil
}

func (redirectErrorHandler) WithConfig(config []byte) (handler.ErrorHandler, error) {
	return nil, nil
}
