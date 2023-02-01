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
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	accesslogmiddleware "github.com/dadrus/heimdall/internal/handler/envoyextauth/grpcv3/middleware/accesslog"
	cachemiddleware "github.com/dadrus/heimdall/internal/handler/envoyextauth/grpcv3/middleware/cache"
	errormiddleware "github.com/dadrus/heimdall/internal/handler/envoyextauth/grpcv3/middleware/errorhandler"
	loggermiddleware "github.com/dadrus/heimdall/internal/handler/envoyextauth/grpcv3/middleware/logger"
	prometheusmiddleware "github.com/dadrus/heimdall/internal/handler/envoyextauth/grpcv3/middleware/prometheus"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules"
)

func newService(
	conf *config.Configuration,
	registerer prometheus.Registerer,
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
			prometheusmiddleware.New(
				prometheusmiddleware.WithServiceName("decision"),
				prometheusmiddleware.WithRegisterer(registerer),
			),
		)
	}

	interceptors = append(interceptors,
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
		accesslogmiddleware.New(logger),
		loggermiddleware.New(logger),
		cachemiddleware.New(cch),
	)

	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(interceptors...))

	envoy_auth.RegisterAuthorizationServer(srv, &Handler{r: repository, s: signer})

	return srv
}
