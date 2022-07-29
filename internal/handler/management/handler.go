package management

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/etag"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/keystore"
)

type Handler struct{}

type handlerParams struct {
	fx.In

	App      *fiber.App `name:"management"`
	KeyStore keystore.KeyStore
	Logger   zerolog.Logger
}

func newHandler(params handlerParams) (*Handler, error) {
	handler := &Handler{}

	handler.registerRoutes(params.App.Group("/"), params.Logger, params.KeyStore)

	return handler, nil
}

func (h *Handler) registerRoutes(router fiber.Router, logger zerolog.Logger, ks keystore.KeyStore) {
	logger.Debug().Msg("Registering Management service routes")

	router.Get(EndpointHealth, health)
	router.Get(EndpointJWKS, etag.New(), jwks(ks))
}
