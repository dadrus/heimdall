// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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
	"errors"
	"net/http"
	"net/http/httputil"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

type committer struct {
	roundTripper http.RoundTripper
}

func newCommitter(rt http.RoundTripper) *committer {
	return &committer{
		roundTripper: rt,
	}
}

func (c *committer) Commit(rw http.ResponseWriter, rc *requestContext) (struct{}, error) {
	if !rc.hasUpstreamTarget {
		return struct{}{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"No upstream reference defined",
		)
	}

	logger := zerolog.Ctx(rc.Context())

	logger.Info().
		Str("_method", rc.Request().Method).
		Str("_upstream", rc.routingURL.String()).
		Msg("Forwarding request")

	errHolder := struct {
		err error
	}{}

	proxy := &httputil.ReverseProxy{
		ErrorHandler: func(_ http.ResponseWriter, _ *http.Request, err error) {
			perr := pipeline.ErrCommunication

			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				perr = pipeline.ErrRequestBodyTooLarge
			}

			logger.Error().Err(err).Msg("Proxying error")

			errHolder.err = errorchain.NewWithMessage(perr, "Failed to proxy request").
				CausedBy(err)
		},
		Rewrite: rc.rewriteRequest,
		Transport: otelhttp.NewTransport(
			httpx.NewTraceRoundTripper(c.roundTripper),
			otelhttp.WithSpanNameFormatter(
				func(_ string, req *http.Request) string {
					return req.Proto + " " + req.Method + " " + req.URL.Path + " @" + req.URL.Host
				},
			),
		),
	}

	proxy.ServeHTTP(rw, rc.req)

	return struct{}{}, errHolder.err
}
