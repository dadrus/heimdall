package management

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/justinas/alice"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/accesslog"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/dump"
	errorhandler2 "github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/logger"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/passthrough"
	prometheus3 "github.com/dadrus/heimdall/internal/handler/middleware/http/prometheus"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/recovery"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/loggeradapter"
)

func newService(
	conf *config.Configuration,
	reg prometheus.Registerer,
	log zerolog.Logger,
	signer heimdall.JWTSigner,
) *http.Server {
	cfg := conf.Serve.Management
	eh := errorhandler2.New()
	opFilter := func(req *http.Request) bool { return req.URL.Path == EndpointHealth }

	hc := alice.New(
		accesslog.New(log),
		logger.New(log),
		dump.New(),
		recovery.New(eh),
		func(next http.Handler) http.Handler {
			return otelhttp.NewHandler(
				next,
				"",
				otelhttp.WithTracerProvider(otel.GetTracerProvider()),
				otelhttp.WithServerName("management"),
				otelhttp.WithSpanNameFormatter(func(_ string, req *http.Request) string {
					return fmt.Sprintf("EntryPoint %s %s%s",
						strings.ToLower(req.URL.Scheme), httpx.LocalAddress(req), req.URL.Path)
				}),
				otelhttp.WithFilter(opFilter),
			)
		},
		x.IfThenElseExec(conf.Metrics.Enabled,
			func() func(http.Handler) http.Handler {
				return prometheus3.New(
					prometheus3.WithServiceName("management"),
					prometheus3.WithRegisterer(reg),
					prometheus3.WithOperationFilter(opFilter),
				)
			},
			func() func(http.Handler) http.Handler { return passthrough.New },
		),
		x.IfThenElseExec(cfg.CORS != nil,
			func() func(http.Handler) http.Handler {
				return cors.New(
					cors.Options{
						AllowedOrigins:   cfg.CORS.AllowedOrigins,
						AllowedMethods:   cfg.CORS.AllowedMethods,
						AllowedHeaders:   cfg.CORS.AllowedHeaders,
						AllowCredentials: cfg.CORS.AllowCredentials,
						ExposedHeaders:   cfg.CORS.ExposedHeaders,
						MaxAge:           int(cfg.CORS.MaxAge.Seconds()),
					},
				).Handler
			},
			func() func(http.Handler) http.Handler { return passthrough.New },
		),
	).Then(newManagementHandler(signer, eh))

	return &http.Server{
		Handler:        hc,
		Addr:           cfg.Address(),
		ReadTimeout:    cfg.Timeout.Read,
		WriteTimeout:   cfg.Timeout.Write,
		IdleTimeout:    cfg.Timeout.Idle,
		MaxHeaderBytes: int(cfg.BufferLimit.Read),
		ErrorLog:       loggeradapter.NewStdLogger(log),
	}
}
