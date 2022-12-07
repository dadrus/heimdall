package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Provide(fx.Annotated{Name: "metrics", Target: newHandler}),
	fx.Invoke(registerHooks),
)

type hooksArgs struct {
	fx.In

	Lifecycle fx.Lifecycle
	Config    config.Configuration
	Logger    zerolog.Logger
	Handler   http.Handler `name:"metrics"`
}

func registerHooks(args hooksArgs) {
	addr := args.Config.Metrics.Prometheus.Address()
	server := &http.Server{
		Addr:              addr,
		Handler:           args.Handler,
		ReadHeaderTimeout: 5 * time.Second, //nolint:gomnd
	}

	args.Lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					// service connections
					args.Logger.Info().Str("_address", addr).Msg("Prometheus service starts listening")
					if err := server.ListenAndServe(); err != nil {
						args.Logger.Fatal().Err(err).Msg("Could not start Prometheus service")
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				args.Logger.Info().Msg("Tearing down Prometheus service")

				return server.Shutdown(ctx)
			},
		},
	)
}
