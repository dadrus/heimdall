package decision

import (
	"context"
	"strings"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	accesslogmiddleware "github.com/dadrus/heimdall/internal/fiber/middleware/accesslog"
	cachemiddleware "github.com/dadrus/heimdall/internal/fiber/middleware/cache"
	errorhandlermiddleware "github.com/dadrus/heimdall/internal/fiber/middleware/errorhandler"
	loggermiddlerware "github.com/dadrus/heimdall/internal/fiber/middleware/logger"
	tracingmiddleware "github.com/dadrus/heimdall/internal/fiber/middleware/opentelemetry"
	"github.com/dadrus/heimdall/internal/x"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Provide(fx.Annotated{Name: "decision", Target: newFiberApp}),
	fx.Invoke(
		newHandler,
		registerHooks,
	),
)

func newFiberApp(conf config.Configuration, cache cache.Cache, logger zerolog.Logger) *fiber.App {
	service := conf.Serve.Decision

	app := fiber.New(fiber.Config{
		AppName:                 "Heimdall Decision Service",
		ReadTimeout:             service.Timeout.Read,
		WriteTimeout:            service.Timeout.Write,
		IdleTimeout:             service.Timeout.Idle,
		DisableStartupMessage:   true,
		EnableTrustedProxyCheck: true,
		TrustedProxies: x.IfThenElseExec(service.TrustedProxies != nil,
			func() []string { return *service.TrustedProxies },
			func() []string { return []string{} }),
		JSONDecoder: json.Unmarshal,
		JSONEncoder: json.Marshal,
	})

	app.Use(recover.New(recover.Config{EnableStackTrace: true}))
	app.Use(tracingmiddleware.New(
		tracingmiddleware.WithTracer(otel.GetTracerProvider().Tracer("github.com/dadrus/heimdall/decision"))))
	app.Use(accesslogmiddleware.New(logger))
	app.Use(loggermiddlerware.New(logger))

	if service.CORS != nil {
		app.Use(cors.New(cors.Config{
			AllowOrigins:     strings.Join(service.CORS.AllowedOrigins, ","),
			AllowMethods:     strings.Join(service.CORS.AllowedMethods, ","),
			AllowHeaders:     strings.Join(service.CORS.AllowedHeaders, ","),
			AllowCredentials: service.CORS.AllowCredentials,
			ExposeHeaders:    strings.Join(service.CORS.ExposedHeaders, ","),
			MaxAge:           int(service.CORS.MaxAge.Seconds()),
		}))
	}

	app.Use(errorhandlermiddleware.New(service.VerboseErrors))
	app.Use(cachemiddleware.New(cache))

	return app
}

type fiberApp struct {
	fx.In

	App *fiber.App `name:"decision"`
}

func registerHooks(lifecycle fx.Lifecycle, logger zerolog.Logger, app fiberApp, conf config.Configuration) {
	service := conf.Serve.Decision

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					// service connections
					addr := service.Address()
					logger.Info().Str("address", addr).Msg("Decision service starts listening")
					if service.TLS != nil {
						if err := app.App.ListenTLS(addr, service.TLS.Cert, service.TLS.Key); err != nil {
							logger.Fatal().Err(err).Msg("Could not start Decision service")
						}
					} else {
						if err := app.App.Listen(addr); err != nil {
							logger.Fatal().Err(err).Msg("Could not start Decision service")
						}
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down Decision service")

				return app.App.Shutdown()
			},
		},
	)
}
