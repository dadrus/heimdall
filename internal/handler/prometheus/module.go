package prometheus

import (
	"context"

	"github.com/ansrivas/fiberprometheus/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Provide(fx.Annotated{Name: "prometheus", Target: newFiberApp}),
	fx.Invoke(
		registerHooks,
	),
)

func newFiberApp(conf config.Configuration) *fiber.App {
	return fiber.New(fiber.Config{
		AppName:               "Heimdall's Prometheus endpoint",
		DisableStartupMessage: true,
	})
}

type fiberApp struct {
	fx.In

	Proxy      *fiber.App `name:"proxy" optional:"true"`
	API        *fiber.App `name:"api" optional:"true"`
	Management *fiber.App `name:"management" optional:"false"`
	Prometheus *fiber.App `name:"prometheus"`
}

func registerHooks(lifecycle fx.Lifecycle, logger zerolog.Logger, app fiberApp, conf config.Configuration) {
	prometheus := fiberprometheus.New("heimdall")
	prometheus.RegisterAt(app.Prometheus, conf.Metrics.Prometheus.MetricsPath)

	if app.API != nil {
		app.API.Use(prometheus.Middleware)
	}

	if app.Proxy != nil {
		app.Proxy.Use(prometheus.Middleware)
	}

	if app.Proxy != nil {
		app.Management.Use(prometheus.Middleware)
	}

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					// service connections
					addr := conf.Metrics.Prometheus.Address()
					logger.Info().Msgf("Prometheus endpoint starts listening on: %s", addr)
					if err := app.Prometheus.Listen(addr); err != nil {
						logger.Fatal().Err(err).Msg("Could not start Prometheus endpoint")
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down Prometheus endpoint")

				return app.Prometheus.Server().Shutdown()
			},
		},
	)
}
