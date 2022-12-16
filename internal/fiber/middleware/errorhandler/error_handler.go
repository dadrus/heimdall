package errorhandler

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/fiber/middleware/accesslog"
	"github.com/dadrus/heimdall/internal/heimdall"
)

func New(opts ...Option) fiber.Handler {
	options := defaultOptions

	for _, opt := range opts {
		opt(&options)
	}

	h := &handler{opts: options}

	return h.handle
}

type handler struct {
	opts
}

func (h *handler) handle(ctx *fiber.Ctx) error { //nolint:cyclop
	err := ctx.Next()
	if err == nil {
		return nil
	}

	accesslog.AddError(ctx.UserContext(), err)

	switch {
	case errors.Is(err, heimdall.ErrAuthentication):
		h.onAuthenticationError(ctx)
	case errors.Is(err, heimdall.ErrAuthorization):
		h.onAuthorizationError(ctx)
	case errors.Is(err, heimdall.ErrCommunicationTimeout):
		h.onCommunicationTimeoutError(ctx)
	case errors.Is(err, heimdall.ErrCommunication):
		h.onCommunicationError(ctx)
	case errors.Is(err, heimdall.ErrArgument):
		h.onArgumentError(ctx)
	case errors.Is(err, heimdall.ErrMethodNotAllowed):
		h.onBadMethodError(ctx)
	case errors.Is(err, heimdall.ErrNoRuleFound):
		h.onNoRuleError(ctx)
	case errors.Is(err, &heimdall.RedirectError{}):
		var redirectError *heimdall.RedirectError

		errors.As(err, &redirectError)

		return ctx.Redirect(redirectError.RedirectTo.String(), redirectError.Code)
	default:
		logger := zerolog.Ctx(ctx.UserContext())
		logger.Error().Err(err).Msg("Internal error occurred")

		h.onInternalError(ctx)
	}

	if h.verboseErrors {
		return ctx.Format(err)
	}

	return nil
}
