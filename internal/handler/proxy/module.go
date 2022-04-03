package proxy

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/fiber/middleware"
)

// nolint
var Module = fx.Options(
	fx.Provide(fx.Annotated{Name: "proxy", Target: newFiberApp}),
	fx.Invoke(
		newHandler,
		registerHooks,
	),
)

func newFiberApp(conf config.Configuration, cache cache.Cache) *fiber.App {
	proxy := conf.Proxy

	app := fiber.New(fiber.Config{
		AppName:               "Heimdall Proxy",
		ReadTimeout:           proxy.Timeout.Read,
		WriteTimeout:          proxy.Timeout.Write,
		IdleTimeout:           proxy.Timeout.Idle,
		DisableStartupMessage: true,
	})

	app.Use(recover.New())

	if proxy.CORS != nil {
		app.Use(cors.New(cors.Config{
			AllowOrigins:     strings.Join(proxy.CORS.AllowedOrigins, ","),
			AllowMethods:     strings.Join(proxy.CORS.AllowedMethods, ","),
			AllowHeaders:     strings.Join(proxy.CORS.AllowedHeaders, ","),
			AllowCredentials: proxy.CORS.AllowCredentials,
			ExposeHeaders:    strings.Join(proxy.CORS.ExposedHeaders, ","),
			MaxAge:           proxy.CORS.MaxAge,
		}))
	}

	app.Use(middleware.Cache(cache))
	app.Use(middleware.Logger())

	return app
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
					logger.Info().Msgf("Reverse Proxy endpoint starts listening on: %s", addr)
					if err := app.App.Listen(addr); err != nil {
						logger.Fatal().Err(err).Msg("Could not start Reverse Proxy endpoint")
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down Reverse Proxy endpoint")

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
