package errorhandlers

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CompositeErrorHandler []handler.ErrorHandler

func (ceh CompositeErrorHandler) HandleError(ctx context.Context, e error) (err error) {
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

func (CompositeErrorHandler) WithConfig(_ map[string]any) (handler.ErrorHandler, error) {
	return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "reconfiguration not allowed")
}
