package rules

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type compositeErrorHandler []errorHandler

func (eh compositeErrorHandler) Execute(ctx heimdall.Context, exErr error) (ok bool, err error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Handling pipeline error")

	for _, eh := range eh {
		ok, err = eh.Execute(ctx, exErr)
		if err != nil {
			logger.Error().Err(err).Msg(
				"Failed to execute error handler. Falling back to the next or the default one")
		}

		if ok {
			return true, nil
		}
	}

	return false, exErr
}
