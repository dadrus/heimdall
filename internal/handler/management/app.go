package management

import (
	"strings"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	accesslogmiddleware "github.com/dadrus/heimdall/internal/fiber/middleware/accesslog"
	errorhandlermiddleware "github.com/dadrus/heimdall/internal/fiber/middleware/errorhandler"
	loggermiddlerware "github.com/dadrus/heimdall/internal/fiber/middleware/logger"
	tracingmiddleware "github.com/dadrus/heimdall/internal/fiber/middleware/opentelemetry"
	fiberprom "github.com/dadrus/heimdall/internal/fiber/middleware/prometheus"
)

type appArgs struct {
	fx.In

	Config     *config.Configuration
	Registerer prometheus.Registerer
	Logger     zerolog.Logger
}

func newApp(args appArgs) *fiber.App {
	service := args.Config.Serve.Management

	filterHealthEndpoint := func(ctx *fiber.Ctx) bool { return ctx.Path() == EndpointHealth }

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
	app.Use(tracingmiddleware.New(
		tracingmiddleware.WithTracer(otel.GetTracerProvider().Tracer("github.com/dadrus/heimdall/management")),
		tracingmiddleware.WithOperationFilter(filterHealthEndpoint)))
	app.Use(fiberprom.New(
		fiberprom.WithServiceName("management"),
		fiberprom.WithRegisterer(args.Registerer),
		fiberprom.WithOperationFilter(filterHealthEndpoint),
	))
	app.Use(accesslogmiddleware.New(args.Logger))
	app.Use(loggermiddlerware.New(args.Logger))

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
