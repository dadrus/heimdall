package management

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/etag"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Handler struct{}

type handlerArgs struct {
	fx.In

	App    *fiber.App `name:"management"`
	Signer heimdall.JWTSigner
	Logger zerolog.Logger
}

func newHandler(args handlerArgs) (*Handler, error) {
	handler := &Handler{}

	handler.registerRoutes(args.App.Group("/"), args.Logger, args.Signer)

	return handler, nil
}

func (h *Handler) registerRoutes(router fiber.Router, logger zerolog.Logger, signer heimdall.JWTSigner) {
	logger.Debug().Msg("Registering Management service routes")

	router.Get(EndpointHealth, health)
	router.Get(EndpointJWKS, etag.New(), jwks(signer))
}
