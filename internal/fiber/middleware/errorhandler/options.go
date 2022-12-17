package errorhandler

import "github.com/gofiber/fiber/v2"

type opts struct {
	verboseErrors               bool
	onAuthenticationError       func(ctx *fiber.Ctx)
	onAuthorizationError        func(ctx *fiber.Ctx)
	onCommunicationTimeoutError func(ctx *fiber.Ctx)
	onCommunicationError        func(ctx *fiber.Ctx)
	onPreconditionError         func(ctx *fiber.Ctx)
	onBadMethodError            func(ctx *fiber.Ctx)
	onNoRuleError               func(ctx *fiber.Ctx)
	onInternalError             func(ctx *fiber.Ctx)
}

type Option func(*opts)

func WithPreconditionErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onPreconditionError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithAuthenticationErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onAuthenticationError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithAuthorizationErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onAuthorizationError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithCommunicationTimeoutErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onCommunicationTimeoutError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithCommunicationErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onCommunicationError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithInternalServerErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onInternalError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithMethodErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onBadMethodError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithNoRuleErrorCode(code int) Option {
	return func(o *opts) {
		if code != 0 {
			o.onNoRuleError = func(ctx *fiber.Ctx) { ctx.Status(code) }
		}
	}
}

func WithVerboseErrors(flag bool) Option {
	return func(o *opts) {
		o.verboseErrors = flag
	}
}
