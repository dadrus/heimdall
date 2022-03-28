package error_handlers

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type CompositeErrorHandler []handler.ErrorHandler

func (ceh CompositeErrorHandler) HandleError(ctx context.Context, e error) error {
	var err error
	for _, eh := range ceh {
		err = eh.HandleError(ctx, e)
		if err != nil {
			// try next
			continue
		} else {
			return nil
		}
	}
	return err
}

func (CompositeErrorHandler) WithConfig(_ json.RawMessage) (handler.ErrorHandler, error) {
	return nil, errors.New("reconfiguration not allowed")
}
