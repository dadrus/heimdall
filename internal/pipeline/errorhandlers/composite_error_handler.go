package errorhandlers

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/rs/zerolog"
)

type CompositeErrorHandler []ErrorHandler

func (ceh CompositeErrorHandler) HandleError(ctx heimdall.Context, e error) (ok bool, err error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Handling pipeline error")

	for _, eh := range ceh {
		ok, err = eh.HandleError(ctx, e)
		if err != nil {
			return false, err
		}

		if ok {
			return true, nil
		}
	}

	return false, errorchain.NewWithMessage(heimdall.ErrInternal, "no applicable error handler available")
}

func (CompositeErrorHandler) WithConfig(_ map[string]any) (ErrorHandler, error) {
	return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "reconfiguration not allowed")
}
