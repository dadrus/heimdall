package proxy

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

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	fibercache "github.com/dadrus/heimdall/internal/fiber/middleware/cache"
	fiberlogger "github.com/dadrus/heimdall/internal/fiber/middleware/logger"
	fibertracing "github.com/dadrus/heimdall/internal/fiber/middleware/tracing"
	"github.com/dadrus/heimdall/internal/handler/errorhandler"
	"github.com/dadrus/heimdall/internal/handler/health"
	"github.com/dadrus/heimdall/internal/x"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Provide(fx.Annotated{Name: "proxy", Target: newFiberApp}),
	fx.Invoke(
		newHandler,
		registerHooks,
	),
)

func newFiberApp(conf config.Configuration, cache cache.Cache, logger zerolog.Logger) *fiber.App {
	service := conf.Serve.Proxy

	app := fiber.New(fiber.Config{
		AppName:                 "Heimdall Proxy",
		ServerHeader:            "Heimdall",
		ReadTimeout:             service.Timeout.Read,
		WriteTimeout:            service.Timeout.Write,
		IdleTimeout:             service.Timeout.Idle,
		DisableStartupMessage:   true,
		ErrorHandler:            errorhandler.NewErrorHandler(service.VerboseErrors, logger),
		EnableTrustedProxyCheck: service.TrustedProxies != nil,
		TrustedProxies: x.IfThenElseExec(service.TrustedProxies != nil,
			func() []string { return *service.TrustedProxies },
			func() []string { return []string{} }),
		JSONDecoder: json.Unmarshal,
		JSONEncoder: json.Marshal,
	})
	app.Use(recover.New(recover.Config{EnableStackTrace: true}))
	app.Use(fibertracing.New(
		fibertracing.WithTracer(opentracing.GlobalTracer()),
		fibertracing.WithOperationFilter(func(ctx *fiber.Ctx) bool { return ctx.Path() == health.EndpointHealth }),
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

	app.Use(fibercache.New(cache))
	app.Use(fiberlogger.New())

	return app
}

type fiberApp struct {
	fx.In

	App *fiber.App `name:"proxy"`
}

func registerHooks(lifecycle fx.Lifecycle, logger zerolog.Logger, app fiberApp, conf config.Configuration) {
	service := conf.Serve.Proxy

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					// service connections
					addr := service.Address()
					logger.Info().Msgf("Proxy endpoint starts listening on: %s", addr)
					if service.TLS != nil {
						if err := app.App.ListenTLS(addr, service.TLS.Cert, service.TLS.Key); err != nil {
							logger.Fatal().Err(err).Msg("Could not start Proxy endpoint")
						}
					} else {
						if err := app.App.Listen(addr); err != nil {
							logger.Fatal().Err(err).Msg("Could not start Proxy endpoint")
						}
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down Proxy endpoint")

				return app.App.Shutdown()
			},
		},
	)
}
