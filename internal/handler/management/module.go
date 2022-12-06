package management

import (
	"context"
	"strings"

	"github.com/ansrivas/fiberprometheus/v2"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	accesslogmiddleware "github.com/dadrus/heimdall/internal/fiber/middleware/accesslog"
	errorhandlermiddleware "github.com/dadrus/heimdall/internal/fiber/middleware/errorhandler"
	loggermiddlerware "github.com/dadrus/heimdall/internal/fiber/middleware/logger"
	tracingmiddleware "github.com/dadrus/heimdall/internal/fiber/middleware/opentelemetry"
	"github.com/dadrus/heimdall/internal/handler/listener"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Provide(fx.Annotated{Name: "management", Target: newFiberApp}),
	fx.Invoke(
		newHandler,
		registerHooks,
	),
)

func newFiberApp(
	conf config.Configuration,
	prometheus *fiberprometheus.FiberPrometheus,
	logger zerolog.Logger,
) *fiber.App {
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
	app.Use(prometheus.Middleware)
	app.Use(tracingmiddleware.New(
		tracingmiddleware.WithTracer(otel.GetTracerProvider().Tracer("github.com/dadrus/heimdall/management")),
		tracingmiddleware.WithOperationFilter(func(ctx *fiber.Ctx) bool { return ctx.Path() == EndpointHealth })))
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

	return app
}

type fiberApp struct {
	fx.In

	App *fiber.App `name:"management"`
}

func registerHooks(lifecycle fx.Lifecycle, logger zerolog.Logger, app fiberApp, conf config.Configuration) {
	ln, err := listener.New(app.App.Config().Network, conf.Serve.Management)
	if err != nil {
		logger.Fatal().Err(err).Msg("Could not create listener for the Management service")

		return
	}

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					logger.Info().Str("_address", ln.Addr().String()).Msg("Management service starts listening")

					if err = app.App.Listener(ln); err != nil {
						logger.Fatal().Err(err).Msg("Could not start Management service")
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
