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

package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/justinas/alice"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/accesslog"
	cachemiddleware "github.com/dadrus/heimdall/internal/handler/middleware/http/cache"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/dump"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/logger"
	prometheus3 "github.com/dadrus/heimdall/internal/handler/middleware/http/prometheus"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/recovery"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/trustedproxy"
	"github.com/dadrus/heimdall/internal/handler/service"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/loggeradapter"
)

// tlsClientConfig used for test purposes only to
// set the certificate pool for peer certificate verification
// purposes.
var tlsClientConfig *tls.Config // nolint: gochecknoglobals

type deadlineResetter struct{}

func (dr *deadlineResetter) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if val := req.Context().Value(dr); val != nil {
			type DeadlinesResetter interface{ MonitorAndResetDeadlines(bool) }

			monitor, ok := val.(DeadlinesResetter)

			if ok {
				monitor.MonitorAndResetDeadlines(true)

				defer monitor.MonitorAndResetDeadlines(false)
			}
		}

		next.ServeHTTP(rw, req)
	})
}

func (dr *deadlineResetter) contexter(ctx context.Context, con net.Conn) context.Context {
	if tlsCon, ok := con.(*tls.Conn); ok {
		return context.WithValue(ctx, dr, tlsCon.NetConn())
	}

	return context.WithValue(ctx, dr, con)
}

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
	der := &deadlineResetter{}
	cfg := conf.Serve.Proxy
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
		der.handler,
		recovery.New(eh),
		func(next http.Handler) http.Handler {
			return otelhttp.NewHandler(
				next,
				"",
				otelhttp.WithTracerProvider(otel.GetTracerProvider()),
				otelhttp.WithServerName("proxy"),
				otelhttp.WithSpanNameFormatter(func(_ string, req *http.Request) string {
					return fmt.Sprintf("EntryPoint %s %s%s",
						strings.ToLower(req.URL.Scheme), httpx.LocalAddress(req), req.URL.Path)
				}),
			)
		},
		x.IfThenElseExec(conf.Metrics.Enabled,
			func() func(http.Handler) http.Handler {
				return prometheus3.New(prometheus3.WithServiceName("proxy"), prometheus3.WithRegisterer(reg))
			},
			func() func(http.Handler) http.Handler { return passThrough },
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
			func() func(http.Handler) http.Handler { return passThrough },
		),
		cachemiddleware.New(cch),
	).Then(service.NewHandler(newContextFactory(signer, cfg, tlsClientConfig), exec, eh))

	return &http.Server{
		Handler:        hc,
		Addr:           cfg.Address(),
		ReadTimeout:    cfg.Timeout.Read,
		WriteTimeout:   cfg.Timeout.Write,
		IdleTimeout:    cfg.Timeout.Idle,
		MaxHeaderBytes: int(cfg.BufferLimit.Read),
		ErrorLog:       loggeradapter.NewStdLogger(log),
		ConnContext:    der.contexter,
	}
}
