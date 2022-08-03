package management

import (
	"context"
	"strings"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	accesslogmiddleware "github.com/dadrus/heimdall/internal/fiber/middleware/accesslog"
	errorhandlermiddleware "github.com/dadrus/heimdall/internal/fiber/middleware/errorhandler"
	loggermiddlerware "github.com/dadrus/heimdall/internal/fiber/middleware/logger"
	fibertracing "github.com/dadrus/heimdall/internal/fiber/middleware/tracing"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Provide(fx.Annotated{Name: "management", Target: newFiberApp}),
	fx.Invoke(
		newHandler,
		registerHooks,
	),
)

func newFiberApp(conf config.Configuration, logger zerolog.Logger) *fiber.App {
	service := conf.Serve.Management

	app := fiber.New(fiber.Config{
		AppName:                 "Heimdall Management Service",
		ReadTimeout:             service.Timeout.Read,
		WriteTimeout:            service.Timeout.Write,
		IdleTimeout:             service.Timeout.Idle,
		DisableStartupMessage:   true,
		EnableTrustedProxyCheck: true,
		JSONDecoder:             json.Unmarshal,
		JSONEncoder:             json.Marshal,
	})
	app.Use(recover.New(recover.Config{EnableStackTrace: true}))
	app.Use(accesslogmiddleware.New(logger))
	app.Use(loggermiddlerware.New(logger))
	app.Use(fibertracing.New(
		fibertracing.WithTracer(opentracing.GlobalTracer()),
		fibertracing.WithOperationFilter(func(ctx *fiber.Ctx) bool { return ctx.Path() == EndpointHealth }),
		fibertracing.WithSpanObserver(func(span opentracing.Span, ctx *fiber.Ctx) {
			ext.Component.Set(span, "heimdall")
		})))

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

	return app
}

type fiberApp struct {
	fx.In

	App *fiber.App `name:"management"`
}

func registerHooks(lifecycle fx.Lifecycle, logger zerolog.Logger, app fiberApp, conf config.Configuration) {
	service := conf.Serve.Management

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					// service connections
					addr := service.Address()
					logger.Info().Str("address", addr).Msg("Management service starts listening")
					if service.TLS != nil {
						if err := app.App.ListenTLS(addr, service.TLS.Cert, service.TLS.Key); err != nil {
							logger.Fatal().Err(err).Msg("Could not start Management service")
						}
					} else {
						if err := app.App.Listen(addr); err != nil {
							logger.Fatal().Err(err).Msg("Could not start Management service")
						}
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down Management service")

				return app.App.Shutdown()
			},
		},
	)
}
