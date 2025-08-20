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

package admissioncontroller

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/inhies/go-bytesize"
	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/dadrus/heimdall/internal/handler/middleware/http/accesslog"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/dump"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/logger"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/otelmetrics"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/recovery"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/admissioncontroller/conversion"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/admissioncontroller/validation"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/loggeradapter"
)

type errorHandlerFunc func(http.ResponseWriter, *http.Request, error)

func (f errorHandlerFunc) HandleError(rw http.ResponseWriter, req *http.Request, err error) {
	f(rw, req, err)
}

func newService(
	serviceName string,
	ruleFactory rule.Factory,
	authClass string,
	log zerolog.Logger,
) *http.Server {
	hc := alice.New(
		accesslog.New(log),
		logger.New(log),
		dump.New(),
		recovery.New(errorHandlerFunc(func(rw http.ResponseWriter, _ *http.Request, _ error) {
			rw.WriteHeader(http.StatusInternalServerError)
		})),
		otelhttp.NewMiddleware("",
			otelhttp.WithServerName(serviceName),
			otelhttp.WithSpanNameFormatter(func(_ string, req *http.Request) string {
				return fmt.Sprintf("EntryPoint %s %s%s",
					strings.ToLower(req.URL.Scheme), httpx.LocalAddress(req), req.URL.Path)
			}),
		),
		otelmetrics.New(
			otelmetrics.WithSubsystem("admission webhooks"),
			otelmetrics.WithServerName(serviceName),
		),
	).Then(newHandler(ruleFactory, authClass))

	return &http.Server{
		Handler:        hc,
		ReadTimeout:    5 * time.Second,      //nolint:mnd
		WriteTimeout:   10 * time.Second,     //nolint:mnd
		IdleTimeout:    90 * time.Second,     //nolint:mnd
		MaxHeaderBytes: int(4 * bytesize.KB), //nolint:mnd
		ErrorLog:       loggeradapter.NewStdLogger(log),
	}
}

func newHandler(ruleFactory rule.Factory, authClass string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/validate-ruleset", validation.NewHandler(ruleFactory, authClass))
	mux.Handle("/convert-rulesets", conversion.NewHandler(ruleFactory, authClass))

	return mux
}
