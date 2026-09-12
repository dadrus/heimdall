// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package grpcv3

import (
	"math"
	"time"

	"github.com/ccoveille/go-safecast/v2"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	cachemiddleware "github.com/dadrus/heimdall/internal/handler/middleware/grpc/cache"
	"github.com/dadrus/heimdall/internal/handler/middleware/grpc/errorhandler"
	loggermiddleware "github.com/dadrus/heimdall/internal/handler/middleware/grpc/logger"
	"github.com/dadrus/heimdall/internal/handler/middleware/grpc/otelmetrics"
	"github.com/dadrus/heimdall/internal/handler/middleware/grpc/requestlimit"
	"github.com/dadrus/heimdall/internal/handler/middleware/grpc/trustedproxy"
	"github.com/dadrus/heimdall/internal/handler/requestcoordinator"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x"
)

func newService(
	conf *config.Configuration,
	cch cache.Cache,
	logger zerolog.Logger,
	exec pipeline.Executor,
) *grpc.Server {
	cfg := conf.Serve
	logHandler := loggermiddleware.New(logger, loggermiddleware.WithAccessLogEnabled(conf.Log.AccessLogEnabled))
	recoveryHandler := recovery.WithRecoveryHandler(func(any) error {
		return status.Error(codes.Internal, "internal error")
	})

	metrics := otelmetrics.New(
		otelmetrics.WithServerName(cfg.Address()),
		otelmetrics.WithSubsystem("decision"),
	)

	unknownServiceHandler := grpc.StreamHandler(func(_ any, _ grpc.ServerStream) error {
		return status.Error(codes.Unknown, "unknown service or method")
	})
	unknownServiceHandler = logHandler.UnknownServiceHandler(unknownServiceHandler)
	unknownServiceHandler = metrics.UnknownServiceHandler(unknownServiceHandler)

	srv := grpc.NewServer(
		grpc.MaxHeaderListSize(safecast.MustConvert[uint32](cfg.Requests.Headers.MaxSize)),
		grpc.MaxConcurrentStreams(safecast.MustConvert[uint32](cfg.Connections.Streams.MaxConcurrent)),
		grpc.MaxRecvMsgSize(x.IfThenElse(
			cfg.Requests.Body.MaxSize > 0,
			safecast.MustConvert[int](cfg.Requests.Body.MaxSize),
			math.MaxInt,
		)),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: cfg.Connections.IdleTimeout,
			Timeout:           cfg.Connections.Liveness.ProbeTimeout,
			Time: x.IfThenElse(
				cfg.Connections.Liveness.ProbeAfter != 0,
				cfg.Connections.Liveness.ProbeAfter,
				time.Duration(math.MaxInt64),
			),
		}),
		grpc.UnknownServiceHandler(unknownServiceHandler),
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			recovery.UnaryServerInterceptor(recoveryHandler),
			trustedproxy.New(logger, cfg.TrustedProxies...),
			metrics.UnaryServerInterceptor(),
			errorhandler.New(
				errorhandler.WithVerboseErrors(cfg.Respond.Verbose),
				errorhandler.WithPreconditionErrorCode(cfg.Respond.With.ArgumentError.Code),
				errorhandler.WithAuthenticationErrorCode(cfg.Respond.With.AuthenticationError.Code),
				errorhandler.WithAuthorizationErrorCode(cfg.Respond.With.AuthorizationError.Code),
				errorhandler.WithCommunicationErrorCode(cfg.Respond.With.CommunicationError.Code),
				errorhandler.WithNoRuleErrorCode(cfg.Respond.With.NoRuleError.Code),
				errorhandler.WithInternalServerErrorCode(cfg.Respond.With.InternalError.Code),
				errorhandler.WithTooManyRequestsErrorCode(cfg.Respond.With.TooManyRequests.Code),
			),
			// the logHandler is used here to have access to the error object
			// as it will be replaced by a CheckResponse object returned to envoy
			// and will not contain all the details, typically required to enable
			// error traceback
			logHandler.UnaryServerInterceptor(),
			requestlimit.New(cfg.Requests.MaxInFlight),
			cachemiddleware.New(cch),
		),
	)

	coordinator := requestcoordinator.New(
		exec,
		newContextFactory(),
		newCommitter(),
	)

	envoy_auth.RegisterAuthorizationServer(srv, &Handler{c: coordinator})

	return srv
}
