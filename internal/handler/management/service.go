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
	"fmt"
	"net/http"
	"strings"

	"github.com/justinas/alice"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/accesslog"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/dump"
	errorhandler2 "github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/logger"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/otelmetrics"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/passthrough"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/recovery"
	"github.com/dadrus/heimdall/internal/keyholder"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/loggeradapter"
)

func newService(
	conf *config.Configuration,
	log zerolog.Logger,
	khr keyholder.Registry,
) *http.Server {
	cfg := conf.Serve.Management
	eh := errorhandler2.New()
	opFilter := func(req *http.Request) bool { return req.URL.Path != EndpointHealth }

	hc := alice.New(
		accesslog.New(log),
		logger.New(log),
		dump.New(),
		recovery.New(eh),
		otelhttp.NewMiddleware("",
			otelhttp.WithServerName(cfg.Address()),
			otelhttp.WithFilter(opFilter),
			otelhttp.WithSpanNameFormatter(func(_ string, req *http.Request) string {
				return fmt.Sprintf("EntryPoint %s %s%s",
					strings.ToLower(req.URL.Scheme), httpx.LocalAddress(req), req.URL.Path)
			}),
		),
		otelmetrics.New(
			otelmetrics.WithSubsystem("management"),
			otelmetrics.WithServerName(cfg.Address()),
			otelmetrics.WithOperationFilter(opFilter),
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
	).Then(newManagementHandler(khr, eh))

	return &http.Server{
		Handler:        hc,
		ReadTimeout:    cfg.Timeout.Read,
		WriteTimeout:   cfg.Timeout.Write,
		IdleTimeout:    cfg.Timeout.Idle,
		MaxHeaderBytes: int(cfg.BufferLimit.Read),
		ErrorLog:       loggeradapter.NewStdLogger(log),
	}
}
