package rules

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type compositeErrorHandler []errorHandler

func (eh compositeErrorHandler) Execute(ctx heimdall.Context, e error) (ok bool, err error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Handling pipeline error")

	for _, eh := range eh {
		ok, err = eh.Execute(ctx, e)
		if err != nil {
			return false, err
		}

		if ok {
			return true, nil
		}
	}

	return false, errorchain.NewWithMessage(heimdall.ErrInternal, "no applicable error handler available")
}
