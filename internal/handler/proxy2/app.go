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

package proxy2

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
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/accesslog"
	cachemiddleware "github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/cache"
	"github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/dump"
	"github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/errorhandler"
	"github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/logger"
	prometheusmiddleware "github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/prometheus"
	"github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/recovery"
	"github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/trustedproxy"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
)

type appArgs struct {
	fx.In

	Config     *config.Configuration
	Registerer prometheus.Registerer
	Cache      cache.Cache
	Logger     zerolog.Logger

	RulesRepository rule.Repository
	Signer          heimdall.JWTSigner
}

func passThrough(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { next.ServeHTTP(rw, req) })
}

func newApp(args appArgs) *http.Server {
	service := args.Config.Serve.Proxy

	eh := errorhandler.New(
		errorhandler.WithVerboseErrors(service.Respond.Verbose),
		errorhandler.WithPreconditionErrorCode(service.Respond.With.ArgumentError.Code),
		errorhandler.WithAuthenticationErrorCode(service.Respond.With.AuthenticationError.Code),
		errorhandler.WithAuthorizationErrorCode(service.Respond.With.AuthorizationError.Code),
		errorhandler.WithCommunicationErrorCode(service.Respond.With.CommunicationError.Code),
		errorhandler.WithMethodErrorCode(service.Respond.With.BadMethodError.Code),
		errorhandler.WithNoRuleErrorCode(service.Respond.With.NoRuleError.Code),
		errorhandler.WithInternalServerErrorCode(service.Respond.With.InternalError.Code),
	)

	hc := alice.New(
		trustedproxy.New(
			x.IfThenElseExec(service.TrustedProxies != nil,
				func() []string { return *service.TrustedProxies },
				func() []string { return []string{} },
			)...,
		),
		accesslog.New(args.Logger),
		logger.New(args.Logger),
		recovery.New(),
		func(next http.Handler) http.Handler {
			return otelhttp.NewHandler(
				next,
				"",
				otelhttp.WithTracerProvider(otel.GetTracerProvider()),
				otelhttp.WithServerName("proxy"),
				otelhttp.WithSpanNameFormatter(func(_ string, req *http.Request) string {
					return fmt.Sprintf("EntryPoint %s %s%s",
						strings.ToLower(req.URL.Scheme), "ctx.Context().LocalAddr().String()", req.URL.Path)
				}),
			)
		},
		x.IfThenElseExec(args.Config.Metrics.Enabled,
			func() func(http.Handler) http.Handler {
				return prometheusmiddleware.New(
					prometheusmiddleware.WithServiceName("proxy"),
					prometheusmiddleware.WithRegisterer(args.Registerer),
				)
			},
			func() func(http.Handler) http.Handler { return passThrough },
		),
		dump.New(),
		x.IfThenElseExec(service.CORS != nil,
			func() func(http.Handler) http.Handler {
				return cors.New(
					cors.Options{
						AllowedOrigins:   service.CORS.AllowedOrigins,
						AllowedMethods:   service.CORS.AllowedMethods,
						AllowedHeaders:   service.CORS.AllowedHeaders,
						AllowCredentials: service.CORS.AllowCredentials,
						ExposedHeaders:   service.CORS.ExposedHeaders,
						MaxAge:           int(service.CORS.MaxAge.Seconds()),
					},
				).Handler
			},
			func() func(http.Handler) http.Handler { return passThrough },
		),
		cachemiddleware.New(args.Cache),
	).Then(newHandler(args.RulesRepository, args.Signer, service.Timeout.Read, eh))

	srv := &http.Server{
		Handler:        hc,
		Addr:           service.Address(),
		ReadTimeout:    service.Timeout.Read,
		WriteTimeout:   service.Timeout.Write,
		IdleTimeout:    service.Timeout.Idle,
		MaxHeaderBytes: int(service.BufferLimit.Read),
		ErrorLog:       newStdLogger(args.Logger),
	}

	return srv
}
