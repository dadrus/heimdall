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

package decision

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/accesslog"
	cachemiddleware "github.com/dadrus/heimdall/internal/handler/middleware/http/cache"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/dump"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/logger"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/otelmetrics"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/recovery"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/trustedproxy"
	"github.com/dadrus/heimdall/internal/handler/service"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/loggeradapter"
)

func newService(
	conf *config.Configuration,
	cch cache.Cache,
	log zerolog.Logger,
	exec rule.Executor,
) *http.Server {
	cfg := conf.Serve.Decision
	eh := errorhandler.New(
		errorhandler.WithVerboseErrors(cfg.Respond.Verbose),
		errorhandler.WithPreconditionErrorCode(cfg.Respond.With.ArgumentError.Code),
		errorhandler.WithAuthenticationErrorCode(cfg.Respond.With.AuthenticationError.Code),
		errorhandler.WithAuthorizationErrorCode(cfg.Respond.With.AuthorizationError.Code),
		errorhandler.WithCommunicationErrorCode(cfg.Respond.With.CommunicationError.Code),
		errorhandler.WithNoRuleErrorCode(cfg.Respond.With.NoRuleError.Code),
		errorhandler.WithInternalServerErrorCode(cfg.Respond.With.InternalError.Code),
	)
	acceptedCode := x.IfThenElse(cfg.Respond.With.Accepted.Code != 0, cfg.Respond.With.Accepted.Code, http.StatusOK)

	hc := alice.New(
		trustedproxy.New(
			log,
			x.IfThenElseExec(cfg.TrustedProxies != nil,
				func() []string { return *cfg.TrustedProxies },
				func() []string { return []string{} },
			)...,
		),
		recovery.New(eh),
		otelhttp.NewMiddleware("",
			otelhttp.WithServerName(cfg.Address()),
			otelhttp.WithSpanNameFormatter(func(_ string, req *http.Request) string {
				return fmt.Sprintf("EntryPoint %s %s%s",
					strings.ToLower(req.URL.Scheme), httpx.LocalAddress(req), req.URL.Path)
			}),
		),
		otelmetrics.New(
			otelmetrics.WithSubsystem("decision"),
			otelmetrics.WithServerName(cfg.Address()),
		),
		accesslog.New(log),
		logger.New(log),
		dump.New(),
		cachemiddleware.New(cch),
	).Then(service.NewHandler(newContextFactory(acceptedCode), exec, eh))

	return &http.Server{
		Handler:        hc,
		ReadTimeout:    cfg.Timeout.Read,
		WriteTimeout:   cfg.Timeout.Write,
		IdleTimeout:    cfg.Timeout.Idle,
		MaxHeaderBytes: int(cfg.BufferLimit.Read),
		ErrorLog:       loggeradapter.NewStdLogger(log),
	}
}
