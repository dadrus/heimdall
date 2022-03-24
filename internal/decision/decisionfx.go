package decision

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/rs/zerolog"

	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/middleware"
)

var Module = fx.Options(
	fx.Provide(fx.Annotated{Name: "api", Target: newFiberApp}),
	fx.Invoke(
		newHandler,
		registerHooks,
	),
)

func newFiberApp(conf config.Configuration) *fiber.App {
	c := conf.DecisionApi

	app := fiber.New(fiber.Config{
		AppName:      "NGKeeper Decision API",
		ReadTimeout:  c.Timeout.Read,
		WriteTimeout: c.Timeout.Write,
		IdleTimeout:  c.Timeout.Idle,
	})
	app.Use(recover.New())

	if c.CORS != nil {
		app.Use(cors.New(cors.Config{
			AllowOrigins:     strings.Join(c.CORS.AllowedOrigins, ","),
			AllowMethods:     strings.Join(c.CORS.AllowedMethods, ","),
			AllowHeaders:     strings.Join(c.CORS.AllowedHeaders, ","),
			AllowCredentials: c.CORS.AllowCredentials,
			ExposeHeaders:    strings.Join(c.CORS.ExposedHeaders, ","),
			MaxAge:           c.CORS.MaxAge,
		}))
	}
	app.Use(middleware.Logger())

	return app
}

type fiberApp struct {
	fx.In

	App *fiber.App `name:"api"`
}

func registerHooks(lifecycle fx.Lifecycle, logger zerolog.Logger, app fiberApp, conf config.Configuration) {
	c := conf.DecisionApi

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					// service connections
					addr := c.Address()
					logger.Info().Msgf("Decision API starts listening on: %s", addr)
					if c.TLS != nil {
						app.App.ListenTLS(addr, c.TLS.Cert, c.TLS.Key)
					} else {
						app.App.Listen(addr)
					}
					if err := app.App.Listen(addr); err != nil {
						logger.Fatal().Err(err).Msg("Decision API terminated unexpected")
					}
				}()
				return nil
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down Decision API!")
				return app.App.Shutdown()
			},
		},
	)
}
