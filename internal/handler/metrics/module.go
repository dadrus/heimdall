package metrics

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Provide(fx.Annotated{Name: "metrics", Target: newFiberApp}),
	fx.Invoke(
		newHandler,
		registerHooks,
	),
)

func newFiberApp() *fiber.App {
	return fiber.New(fiber.Config{
		AppName:               "Heimdall's Prometheus endpoint",
		DisableStartupMessage: true,
	})
}

type hooksArgs struct {
	fx.In

	Lifecycle fx.Lifecycle
	Config    config.Configuration
	Logger    zerolog.Logger
	App       *fiber.App `name:"metrics"`
}

func registerHooks(args hooksArgs) {
	args.Lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					addr := args.Config.Metrics.Prometheus.Address()
					args.Logger.Info().Str("_address", addr).Msg("Prometheus service starts listening")
					if err := args.App.Listen(addr); err != nil {
						args.Logger.Fatal().Err(err).Msg("Could not start Prometheus service")
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				args.Logger.Info().Msg("Tearing down Prometheus service")

				return args.App.Shutdown()
			},
		},
	)
}
