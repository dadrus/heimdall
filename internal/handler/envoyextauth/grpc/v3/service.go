package v3

import (
    envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
    "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/rs/zerolog"
    "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
    "google.golang.org/grpc"

    "github.com/dadrus/heimdall/internal/cache"
    "github.com/dadrus/heimdall/internal/config"
    accesslogmiddleware "github.com/dadrus/heimdall/internal/handler/envoyextauth/grpc/middleware/accesslog"
    cachemiddleware "github.com/dadrus/heimdall/internal/handler/envoyextauth/grpc/middleware/cache"
    errormiddleware "github.com/dadrus/heimdall/internal/handler/envoyextauth/grpc/middleware/errorhandler"
    loggermiddleware "github.com/dadrus/heimdall/internal/handler/envoyextauth/grpc/middleware/logger"
    prometheus2 "github.com/dadrus/heimdall/internal/handler/envoyextauth/grpc/middleware/prometheus"
    "github.com/dadrus/heimdall/internal/heimdall"
    "github.com/dadrus/heimdall/internal/rules"
)

func newService(
    conf *config.Configuration,
    registrer prometheus.Registerer,
    cch cache.Cache,
    logger zerolog.Logger,
    repository rules.Repository,
    signer heimdall.JWTSigner,
) *grpc.Server {
    service := conf.Serve.Decision

    interceptors := []grpc.UnaryServerInterceptor{
        grpc_recovery.UnaryServerInterceptor(),
        otelgrpc.UnaryServerInterceptor(),
    }

    if conf.Metrics.Enabled {
        interceptors = append(interceptors,
            prometheus2.New(
                prometheus2.WithServiceName("decision"),
                prometheus2.WithRegisterer(registrer),
            ),
        )
    }

    interceptors = append(interceptors,
        accesslogmiddleware.New(logger),
        loggermiddleware.New(logger),
        errormiddleware.New(
            errormiddleware.WithVerboseErrors(service.Respond.Verbose),
            errormiddleware.WithPreconditionErrorCode(service.Respond.With.ArgumentError.Code),
            errormiddleware.WithAuthenticationErrorCode(service.Respond.With.AuthenticationError.Code),
            errormiddleware.WithAuthorizationErrorCode(service.Respond.With.AuthorizationError.Code),
            errormiddleware.WithCommunicationErrorCode(service.Respond.With.CommunicationError.Code),
            errormiddleware.WithMethodErrorCode(service.Respond.With.BadMethodError.Code),
            errormiddleware.WithNoRuleErrorCode(service.Respond.With.NoRuleError.Code),
            errormiddleware.WithInternalServerErrorCode(service.Respond.With.InternalError.Code),
        ),
        cachemiddleware.New(cch),
    )

    srv := grpc.NewServer(grpc.ChainUnaryInterceptor(interceptors...))

    envoy_auth.RegisterAuthorizationServer(srv, &Handler{r: repository, s: signer})

    return srv
}
