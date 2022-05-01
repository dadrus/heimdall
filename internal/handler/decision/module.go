package decision

import (
	"context"
	"strings"

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
	"github.com/dadrus/heimdall/internal/x"
)

// nolint
var Module = fx.Options(
	fx.Provide(fx.Annotated{Name: "api", Target: newFiberApp}),
	fx.Invoke(
		newHandler,
		registerHooks,
	),
)

func newFiberApp(conf config.Configuration, cache cache.Cache, logger zerolog.Logger) *fiber.App {
	api := conf.Serve.DecisionAPI

	app := fiber.New(fiber.Config{
		AppName:                 "Heimdall Decision API",
		ServerHeader:            "Heimdall Decision API",
		ReadTimeout:             api.Timeout.Read,
		WriteTimeout:            api.Timeout.Write,
		IdleTimeout:             api.Timeout.Idle,
		DisableStartupMessage:   true,
		ErrorHandler:            errorhandler.NewErrorHandler(api.VerboseErrors, logger),
		EnableTrustedProxyCheck: api.TrustedProxies != nil,
		TrustedProxies: x.IfThenElseExec(
			api.TrustedProxies != nil,
			func() []string { return *api.TrustedProxies },
			func() []string { return []string{} }),
	})
	app.Use(recover.New(recover.Config{EnableStackTrace: true}))

	if api.CORS != nil {
		app.Use(cors.New(cors.Config{
			AllowOrigins:     strings.Join(api.CORS.AllowedOrigins, ","),
			AllowMethods:     strings.Join(api.CORS.AllowedMethods, ","),
			AllowHeaders:     strings.Join(api.CORS.AllowedHeaders, ","),
			AllowCredentials: api.CORS.AllowCredentials,
			ExposeHeaders:    strings.Join(api.CORS.ExposedHeaders, ","),
			MaxAge:           int(api.CORS.MaxAge.Seconds()),
		}))
	}

	app.Use(fibertracing.New(
		fibertracing.WithTracer(opentracing.GlobalTracer()),
		fibertracing.WithSpanObserver(func(span opentracing.Span, ctx *fiber.Ctx) {
			ext.Component.Set(span, "heimdall")
		})))
	app.Use(fibercache.New(cache))
	app.Use(fiberlogger.New())

	return app
}

type fiberApp struct {
	fx.In

	App *fiber.App `name:"api"`
}

func registerHooks(lifecycle fx.Lifecycle, logger zerolog.Logger, app fiberApp, conf config.Configuration) {
	apiConf := conf.Serve.DecisionAPI

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					// service connections
					addr := apiConf.Address()
					logger.Info().Msgf("Decision API endpoint starts listening on: %s", addr)
					if apiConf.TLS != nil {
						if err := app.App.ListenTLS(addr, apiConf.TLS.Cert, apiConf.TLS.Key); err != nil {
							logger.Fatal().Err(err).Msg("Could not start Decision API endpoint")
						}
					} else {
						if err := app.App.Listen(addr); err != nil {
							logger.Fatal().Err(err).Msg("Could not start Decision API endpoint")
						}
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down Decision API endpoint")

				return app.App.Shutdown()
			},
		},
	)
}
