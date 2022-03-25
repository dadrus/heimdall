package proxy

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
)

var Module = fx.Options(
	fx.Provide(fx.Annotated{Name: "proxy", Target: newFiberApp}),
	fx.Invoke(
		newHandler,
		registerHooks,
	),
)

func newFiberApp(conf config.Configuration) *fiber.App {
	return fiber.New(fiber.Config{
		AppName:      "Heimdall Proxy",
		ReadTimeout:  conf.Proxy.Timeout.Read,
		WriteTimeout: conf.Proxy.Timeout.Write,
		IdleTimeout:  conf.Proxy.Timeout.Idle,
	})
}

type fiberApp struct {
	fx.In

	App *fiber.App `name:"proxy"`
}

func registerHooks(lifecycle fx.Lifecycle, logger zerolog.Logger, app fiberApp, conf config.Configuration) {
	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					// service connections
					addr := conf.Proxy.Address()
					logger.Info().Msgf("Reverse Proxy starts listening on: %s", addr)
					if err := app.App.Listen(addr); err != nil {
						logger.Fatal().Err(err).Msg("Reverse Proxy terminated unexpected")
					}
				}()
				return nil
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down Reverse Proxy!")
				return app.App.Server().Shutdown()
			},
		},
	)
}

type Handler struct{}

func newHandler(p fiberApp, logger zerolog.Logger) *Handler {
	h := &Handler{}

	h.registerRoutes(p.App.Group(""), logger)
	return h
}

func (h *Handler) registerRoutes(router fiber.Router, logger zerolog.Logger) {
	logger.Debug().Msg("Registering proxy routes")

	router.Get("/foo", func(c *fiber.Ctx) error {
		return c.SendString("hi from foo")
	})

}
