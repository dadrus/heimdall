package dump

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

func New() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		logger := zerolog.Ctx(ctx.UserContext())

		if logger.GetLevel() != zerolog.TraceLevel {
			return ctx.Next()
		}

		logger.Trace().Msg("Request: \n" + ctx.Context().Request.String())

		err := ctx.Next()
		if err == nil {
			logger.Trace().Msg("Response: \n" + ctx.Context().Response.String())
		}

		return err
	}
}
