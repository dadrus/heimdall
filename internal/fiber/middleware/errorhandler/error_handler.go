package errorhandler

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/fiber/middleware/accesslog"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
)

func New(verbose bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := c.Next(); err != nil {
			acl := accesslog.Ctx(c.UserContext())
			acl.Err = err

			return x.IfThenElse(verbose, verboseErrorHandler, defaultErrorHandler)(c, err)
		}

		return nil
	}
}

func defaultErrorHandler(ctx *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, heimdall.ErrAuthentication):
		ctx.Status(fiber.StatusUnauthorized)
	case errors.Is(err, heimdall.ErrAuthorization):
		ctx.Status(fiber.StatusForbidden)
	case errors.Is(err, heimdall.ErrCommunicationTimeout) || errors.Is(err, heimdall.ErrCommunication):
		ctx.Status(fiber.StatusBadGateway)
	case errors.Is(err, heimdall.ErrArgument):
		ctx.Status(fiber.StatusBadRequest)
	case errors.Is(err, heimdall.ErrMethodNotAllowed):
		ctx.Status(fiber.StatusMethodNotAllowed)
	case errors.Is(err, heimdall.ErrNoRuleFound):
		ctx.Status(fiber.StatusNotFound)
	case errors.Is(err, &heimdall.RedirectError{}):
		var redirectError *heimdall.RedirectError

		errors.As(err, &redirectError)

		return ctx.Redirect(redirectError.RedirectTo.String(), redirectError.Code)
	default:
		logger := zerolog.Ctx(ctx.UserContext())
		logger.Error().Err(err).Msg("Error occurred")

		ctx.Status(fiber.StatusInternalServerError)
	}

	return nil
}

func verboseErrorHandler(ctx *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, heimdall.ErrAuthentication):
		return ctx.Status(fiber.StatusUnauthorized).Format(err)
	case errors.Is(err, heimdall.ErrAuthorization):
		return ctx.Status(fiber.StatusForbidden).Format(err)
	case errors.Is(err, heimdall.ErrCommunicationTimeout) || errors.Is(err, heimdall.ErrCommunication):
		return ctx.Status(fiber.StatusBadGateway).Format(err)
	case errors.Is(err, heimdall.ErrArgument):
		return ctx.Status(fiber.StatusBadRequest).Format(err)
	case errors.Is(err, heimdall.ErrMethodNotAllowed):
		return ctx.Status(fiber.StatusMethodNotAllowed).Format(err)
	case errors.Is(err, heimdall.ErrNoRuleFound):
		return ctx.Status(fiber.StatusNotFound).Format(err)
	case errors.Is(err, &heimdall.RedirectError{}):
		var redirectError *heimdall.RedirectError

		errors.As(err, &redirectError)

		return ctx.Redirect(redirectError.RedirectTo.String(), redirectError.Code)
	default:
		logger := zerolog.Ctx(ctx.UserContext())
		logger.Error().Err(err).Msg("Error occurred")

		return ctx.Status(fiber.StatusInternalServerError).Format(err)
	}
}
