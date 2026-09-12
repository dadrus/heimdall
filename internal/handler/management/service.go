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

package management

import (
	"net/http"
	"strings"

	"github.com/ccoveille/go-safecast/v2"
	"github.com/justinas/alice"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/bodylimit"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/dump"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/ioprogress"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/logger"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/otelmetrics"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/passthrough"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/recovery"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/requestlimit"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/requestvalidation"
	"github.com/dadrus/heimdall/internal/keyregistry"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/loggeradapter"
)

func newService(
	conf *config.Configuration,
	log zerolog.Logger,
	kp keyregistry.JWKSProvider,
) *http.Server {
	cfg := conf.Management
	eh := errorhandler.New()
	opFilter := func(req *http.Request) bool { return req.URL.Path != EndpointHealth }

	hc := alice.New(
		ioprogress.New(
			log,
			ioprogress.WithResponseWriteTimeout(cfg.Responses.WriteTimeout),
			ioprogress.WithResponseWriteIdleTimeout(cfg.Responses.WriteIdleTimeout),
			ioprogress.WithResponseWriteMinRate(cfg.Responses.WriteMinRate),
		),
		recovery.New(eh),
		otelhttp.NewMiddleware("",
			otelhttp.WithServerName(cfg.Address()),
			otelhttp.WithFilter(opFilter),
			otelhttp.WithSpanNameFormatter(func(_ string, req *http.Request) string {
				return "EntryPoint " + strings.ToLower(req.URL.Scheme) + " " + httpx.LocalAddress(req) + req.URL.Path
			}),
		),
		otelmetrics.New(
			otelmetrics.WithSubsystem("management"),
			otelmetrics.WithServerName(cfg.Address()),
			otelmetrics.WithOperationFilter(opFilter),
		),
		logger.New(log, logger.WithAccessLogEnabled(conf.Log.AccessLogEnabled)),
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
	).Then(newHandler(kp, eh))

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(cfg.TLS != nil)
	protocols.SetUnencryptedHTTP2(false)

	connectionDefaults := config.DefaultIngressConnections()

	return &http.Server{
		Handler:           hc,
		ReadTimeout:       cfg.Requests.ReadTimeout,
		ReadHeaderTimeout: cfg.Requests.Headers.ReadTimeout,
		WriteTimeout:      cfg.Responses.WriteTimeout,
		IdleTimeout:       cfg.Connections.IdleTimeout,
		MaxHeaderBytes:    safecast.MustConvert[int](uint64(cfg.Requests.Headers.MaxSize)),
		ErrorLog:          loggeradapter.NewStdLogger(log),
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: connectionDefaults.Streams.MaxConcurrent,
			SendPingTimeout:      connectionDefaults.Liveness.ProbeAfter,
			PingTimeout:          connectionDefaults.Liveness.ProbeTimeout,
			WriteByteTimeout:     connectionDefaults.WriteIdleTimeout,
		},
		Protocols: protocols,
	}
}
