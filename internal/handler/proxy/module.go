package proxy

import (
	"context"
	"github.com/ansrivas/fiberprometheus/v2"
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
	fiberproxy "github.com/dadrus/heimdall/internal/fiber/middleware/proxyheader"
	"github.com/dadrus/heimdall/internal/handler/listener"
	"github.com/dadrus/heimdall/internal/x"
)

var Module = fx.Options( // nolint: gochecknoglobals
	fx.Provide(fx.Annotated{Name: "proxy", Target: newFiberApp}),
	fx.Invoke(
		newHandler,
		registerHooks,
	),
)

func newFiberApp(
	conf config.Configuration,
	prometheus *fiberprometheus.FiberPrometheus,
	cache cache.Cache,
	logger zerolog.Logger,
) *fiber.App {
	service := conf.Serve.Proxy

	app := fiber.New(fiber.Config{
		AppName:                 "Heimdall Proxy Service",
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
	app.Use(prometheus.Middleware)
	app.Use(tracingmiddleware.New(
		tracingmiddleware.WithTracer(otel.GetTracerProvider().Tracer("github.com/dadrus/heimdall/proxy"))))
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
	app.Use(fiberproxy.New())

	return app
}

type fiberApp struct {
	fx.In

	App *fiber.App `name:"proxy"`
}

func registerHooks(lifecycle fx.Lifecycle, logger zerolog.Logger, app fiberApp, conf config.Configuration) {
	ln, err := listener.New(app.App.Config().Network, conf.Serve.Proxy)
	if err != nil {
		logger.Fatal().Err(err).Msg("Could not create listener for the Proxy service")

		return
	}

	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					logger.Info().Str("_address", ln.Addr().String()).Msg("Proxy service starts listening")

					if err = app.App.Listener(ln); err != nil {
						logger.Fatal().Err(err).Msg("Could not start Proxy service")
					}
				}()

				return nil
			},
			OnStop: func(ctx context.Context) error {
				logger.Info().Msg("Tearing down Proxy service")

				return app.App.Shutdown()
			},
		},
	)
}
