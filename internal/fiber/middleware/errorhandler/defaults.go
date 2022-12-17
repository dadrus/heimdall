package errorhandler

import "github.com/gofiber/fiber/v2"

var defaultOptions = opts{ //nolint:gochecknoglobals
	onAuthenticationError: func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusUnauthorized) },
	onAuthorizationError:  func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusForbidden) },
	onCommunicationError:  func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusBadGateway) },
	onPreconditionError:   func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusBadRequest) },
	onBadMethodError:      func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusMethodNotAllowed) },
	onNoRuleError:         func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusNotFound) },
	onInternalError:       func(ctx *fiber.Ctx) { ctx.Status(fiber.StatusInternalServerError) },
}
