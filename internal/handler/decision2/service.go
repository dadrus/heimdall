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

package decision2

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/justinas/alice"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/middleware/accesslog"
	cachemiddleware "github.com/dadrus/heimdall/internal/handler/middleware/cache"
	"github.com/dadrus/heimdall/internal/handler/middleware/dump"
	"github.com/dadrus/heimdall/internal/handler/middleware/errorhandler"
	"github.com/dadrus/heimdall/internal/handler/middleware/logger"
	prometheus2 "github.com/dadrus/heimdall/internal/handler/middleware/prometheus"
	"github.com/dadrus/heimdall/internal/handler/middleware/recovery"
	"github.com/dadrus/heimdall/internal/handler/middleware/trustedproxy"
	"github.com/dadrus/heimdall/internal/handler/service"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/loggeradapter"
)

func passThrough(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { next.ServeHTTP(rw, req) })
}

func newService(
	conf *config.Configuration,
	reg prometheus.Registerer,
	cch cache.Cache,
	log zerolog.Logger,
	exec rule.Executor,
	signer heimdall.JWTSigner,
) *http.Server {
	cfg := conf.Serve.Decision
	eh := errorhandler.New(
		errorhandler.WithVerboseErrors(cfg.Respond.Verbose),
		errorhandler.WithPreconditionErrorCode(cfg.Respond.With.ArgumentError.Code),
		errorhandler.WithAuthenticationErrorCode(cfg.Respond.With.AuthenticationError.Code),
		errorhandler.WithAuthorizationErrorCode(cfg.Respond.With.AuthorizationError.Code),
		errorhandler.WithCommunicationErrorCode(cfg.Respond.With.CommunicationError.Code),
		errorhandler.WithMethodErrorCode(cfg.Respond.With.BadMethodError.Code),
		errorhandler.WithNoRuleErrorCode(cfg.Respond.With.NoRuleError.Code),
		errorhandler.WithInternalServerErrorCode(cfg.Respond.With.InternalError.Code),
	)
	acceptedCode := x.IfThenElse(cfg.Respond.With.Accepted.Code != 0, cfg.Respond.With.Accepted.Code, fiber.StatusOK)

	hc := alice.New(
		trustedproxy.New(
			log,
			x.IfThenElseExec(cfg.TrustedProxies != nil,
				func() []string { return *cfg.TrustedProxies },
				func() []string { return []string{} },
			)...,
		),
		accesslog.New(log),
		logger.New(log),
		dump.New(),
		recovery.New(eh),
		func(next http.Handler) http.Handler {
			return otelhttp.NewHandler(
				next,
				"",
				otelhttp.WithTracerProvider(otel.GetTracerProvider()),
				otelhttp.WithServerName("decision"),
				otelhttp.WithSpanNameFormatter(func(_ string, req *http.Request) string {
					return fmt.Sprintf("EntryPoint %s %s%s",
						strings.ToLower(req.URL.Scheme), getLocalAddress(req), req.URL.Path)
				}),
			)
		},
		x.IfThenElseExec(conf.Metrics.Enabled,
			func() func(http.Handler) http.Handler {
				return prometheus2.New(
					prometheus2.WithServiceName("decision"),
					prometheus2.WithRegisterer(reg),
				)
			},
			func() func(http.Handler) http.Handler { return passThrough },
		),
		cachemiddleware.New(cch),
	).Then(service.NewHandler(newContextFactory(signer, acceptedCode), exec, eh))

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

func getLocalAddress(req *http.Request) string {
	localAddr := "unknown"
	if addr, ok := req.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		localAddr = addr.String()
	}

	return localAddr
}
