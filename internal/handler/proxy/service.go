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
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/ccoveille/go-safecast/v2"
	"github.com/justinas/alice"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/bodylimit"
	cachemiddleware "github.com/dadrus/heimdall/internal/handler/middleware/http/cache"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/dump"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/ioprogress"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/logger"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/otelmetrics"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/passthrough"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/recovery"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/requestlimit"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/requestvalidation"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/trustedproxy"
	"github.com/dadrus/heimdall/internal/handler/requestcoordinator"
	"github.com/dadrus/heimdall/internal/handler/service"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/loggeradapter"
)

// tlsClientConfig used for test purposes only to
// set the certificate pool for peer certificate verification
// purposes.
var tlsClientConfig *tls.Config // nolint: gochecknoglobals

//nolint:funlen
func newService(
	conf *config.Configuration,
	cch cache.Cache,
	log zerolog.Logger,
	exec pipeline.Executor,
) *http.Server {
	cfg := conf.Serve
	eh := errorhandler.New(
		errorhandler.WithVerboseErrors(cfg.Respond.Verbose),
		errorhandler.WithPreconditionErrorCode(cfg.Respond.With.ArgumentError.Code),
		errorhandler.WithAuthenticationErrorCode(cfg.Respond.With.AuthenticationError.Code),
		errorhandler.WithAuthorizationErrorCode(cfg.Respond.With.AuthorizationError.Code),
		errorhandler.WithCommunicationErrorCode(cfg.Respond.With.CommunicationError.Code),
		errorhandler.WithNoRuleErrorCode(cfg.Respond.With.NoRuleError.Code),
		errorhandler.WithInternalServerErrorCode(cfg.Respond.With.InternalError.Code),
		errorhandler.WithRequestBodyTooLargeErrorCode(cfg.Respond.With.RequestBodyTooLarge.Code),
		errorhandler.WithTooManyRequestsErrorCode(cfg.Respond.With.TooManyRequests.Code),
	)
	rt := newObservedRoundTripper(newProfileRoundTripper(cfg, tlsClientConfig))
	coordinator := requestcoordinator.New(exec, newContextFactory(), newCommitter(rt))

	hc := alice.New(
		ioprogress.New(
			log,
			ioprogress.WithRequestReadTimeout(cfg.Requests.ReadTimeout),
			ioprogress.WithRequestBodyReadIdleTimeout(cfg.Requests.Body.ReadIdleTimeout),
			ioprogress.WithRequestBodyReadMinRate(cfg.Requests.Body.ReadMinRate),
			ioprogress.WithResponseWriteTimeout(cfg.Responses.WriteTimeout),
			ioprogress.WithResponseWriteIdleTimeout(cfg.Responses.WriteIdleTimeout),
			ioprogress.WithResponseWriteMinRate(cfg.Responses.WriteMinRate),
		),
		trustedproxy.New(
			log,
			cfg.TrustedProxies...,
		),
		recovery.New(eh),
		otelhttp.NewMiddleware("",
			otelhttp.WithServerName(cfg.Address()),
			otelhttp.WithSpanNameFormatter(func(_ string, req *http.Request) string {
				return "EntryPoint " + strings.ToLower(req.URL.Scheme) + " " + httpx.LocalAddress(req) + req.URL.Path
			}),
		),
		otelmetrics.New(
			otelmetrics.WithSubsystem("proxy"),
			otelmetrics.WithServerName(cfg.Address()),
		),
		logger.New(log,
			logger.WithAccessStatusEnabled(true),
			logger.WithAccessLogEnabled(conf.Log.AccessLogEnabled),
		),
		requestlimit.New(cfg.Requests.MaxInFlight, eh),
		bodylimit.New(cfg.Requests.Body.MaxSize, eh),
		requestvalidation.New(),
		dump.New(),
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
		cachemiddleware.New(cch),
	).Then(service.NewHandler(coordinator, eh))

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(cfg.TLS != nil)
	protocols.SetUnencryptedHTTP2(cfg.TLS == nil)

	return &http.Server{
		Handler:           hc,
		ReadTimeout:       cfg.Requests.ReadTimeout,
		ReadHeaderTimeout: cfg.Requests.Headers.ReadTimeout,
		WriteTimeout:      cfg.Responses.WriteTimeout,
		IdleTimeout:       cfg.Connections.IdleTimeout,
		MaxHeaderBytes:    safecast.MustConvert[int](uint64(cfg.Requests.Headers.MaxSize)),
		ErrorLog:          loggeradapter.NewStdLogger(log),
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: cfg.Connections.Streams.MaxConcurrent,
			SendPingTimeout:      cfg.Connections.Liveness.ProbeAfter,
			PingTimeout:          cfg.Connections.Liveness.ProbeTimeout,
			WriteByteTimeout:     cfg.Connections.WriteIdleTimeout,
		},
		Protocols: protocols,
	}
}
