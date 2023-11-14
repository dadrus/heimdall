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
	accesslogmiddleware "github.com/dadrus/heimdall/internal/handler/middleware/grpc/accesslog"
	cachemiddleware "github.com/dadrus/heimdall/internal/handler/middleware/grpc/cache"
	"github.com/dadrus/heimdall/internal/handler/middleware/grpc/errorhandler"
	loggermiddleware "github.com/dadrus/heimdall/internal/handler/middleware/grpc/logger"
	"github.com/dadrus/heimdall/internal/handler/middleware/grpc/otelmetrics"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

func newService(
	conf *config.Configuration,
	cch cache.Cache,
	logger zerolog.Logger,
	exec rule.Executor,
	signer heimdall.JWTSigner,
) *grpc.Server {
	service := conf.Serve.Decision
	accessLogger := accesslogmiddleware.New(logger)
	recoveryHandler := recovery.WithRecoveryHandler(func(any) error {
		return status.Error(codes.Internal, "internal error")
	})

	metrics := otelmetrics.New(
		otelmetrics.WithServerName(service.Address()),
		otelmetrics.WithSubsystem("decision"),
	)

	streamInterceptors := []grpc.StreamServerInterceptor{
		recovery.StreamServerInterceptor(recoveryHandler),
		metrics.StreamServerInterceptor(),
	}

	unaryInterceptors := []grpc.UnaryServerInterceptor{
		recovery.UnaryServerInterceptor(recoveryHandler),
		metrics.UnaryServerInterceptor(),
	}

	unaryInterceptors = append(unaryInterceptors,
		errorhandler.New(
			errorhandler.WithVerboseErrors(service.Respond.Verbose),
			errorhandler.WithPreconditionErrorCode(service.Respond.With.ArgumentError.Code),
			errorhandler.WithAuthenticationErrorCode(service.Respond.With.AuthenticationError.Code),
			errorhandler.WithAuthorizationErrorCode(service.Respond.With.AuthorizationError.Code),
			errorhandler.WithCommunicationErrorCode(service.Respond.With.CommunicationError.Code),
			errorhandler.WithMethodErrorCode(service.Respond.With.BadMethodError.Code),
			errorhandler.WithNoRuleErrorCode(service.Respond.With.NoRuleError.Code),
			errorhandler.WithInternalServerErrorCode(service.Respond.With.InternalError.Code),
		),
		// the accesslogger is used here to have access to the error object
		// as it will be replaced by a CheckResponse object returned to envoy
		// and will not contain all the details, typically required to enable
		// error traceback
		accessLogger.Unary(),
		loggermiddleware.New(logger),
		cachemiddleware.New(cch),
	)

	streamInterceptors = append(streamInterceptors, accessLogger.Stream())

	srv := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{Timeout: service.Timeout.Idle}),
		grpc.ReadBufferSize(int(service.BufferLimit.Read)),
		grpc.WriteBufferSize(int(service.BufferLimit.Write)),
		grpc.UnknownServiceHandler(func(srv interface{}, stream grpc.ServerStream) error {
			return status.Error(codes.Unknown, "unknown service or method")
		}),
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	)

	envoy_auth.RegisterAuthorizationServer(srv, &Handler{e: exec, s: signer})

	return srv
}
