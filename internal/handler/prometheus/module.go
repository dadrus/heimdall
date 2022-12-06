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
	fx.Provide(func() *fiberprometheus.FiberPrometheus { return fiberprometheus.New("heimdall") }),
	fx.Invoke(registerHooks),
)

func registerHooks(
	lifecycle fx.Lifecycle,
	logger zerolog.Logger,
	prometheus *fiberprometheus.FiberPrometheus,
	conf config.Configuration,
) {
	app := fiber.New(fiber.Config{
		AppName:               "Heimdall's Prometheus endpoint",
		DisableStartupMessage: true,
	})

	prometheus.RegisterAt(app, conf.Metrics.Prometheus.MetricsPath)

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					// service connections
					addr := conf.Metrics.Prometheus.Address()
					logger.Info().Str("_address", addr).Msg("Prometheus service starts listening")
					if err := app.Listen(addr); err != nil {
						logger.Fatal().Err(err).Msg("Could not start Prometheus service")
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down Prometheus service")

				return app.Server().Shutdown()
			},
		},
	)
}
