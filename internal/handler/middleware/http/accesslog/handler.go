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

package accesslog

import (
	"context"
	"net/http"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/accesscontext"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/tracecontext"
)

func New(logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			start := time.Now()
			ctx := accesscontext.New(req.Context())
			req = req.WithContext(ctx)
			host := httpx.IPFromHostPort(req.RemoteAddr)

			logCtx := logger.Level(zerolog.InfoLevel).With().
				Int64("_tx_start", start.Unix()).
				Str("_client_ip", host).
				Str("_http_method", req.Method).
				Str("_http_path", req.URL.Path).
				Str("_http_user_agent", req.Header.Get("User-Agent")).
				Str("_http_host", req.Host).
				Str("_http_scheme", x.IfThenElse(req.TLS != nil, "https", "http"))
			logCtx = logTraceData(ctx, logCtx)

			logCtx = logHeader(req, logCtx, "X-Forwarded-Method", "_http_x_forwarded_method")
			logCtx = logHeader(req, logCtx, "X-Forwarded-Proto", "_http_x_forwarded_proto")
			logCtx = logHeader(req, logCtx, "X-Forwarded-Host", "_http_x_forwarded_host")
			logCtx = logHeader(req, logCtx, "X-Forwarded-Uri", "_http_x_forwarded_uri")
			logCtx = logHeader(req, logCtx, "X-Forwarded-For", "_http_x_forwarded_for")
			logCtx = logHeader(req, logCtx, "Forwarded", "_http_forwarded")

			accLog := logCtx.Logger()
			accLog.Info().Msg("TX started")

			metrics := httpsnoop.CaptureMetrics(next, rw, req)

			logAccessStatus(ctx, accLog.Info(), metrics.Code).
				Int64("_body_bytes_sent", metrics.Written).
				Int("_http_status_code", metrics.Code).
				Int64("_tx_duration_ms", time.Until(start).Milliseconds()).
				Msg("TX finished")
		})
	}
}

func logAccessStatus(ctx context.Context, event *zerolog.Event, statusCode int) *zerolog.Event {
	subject := accesscontext.Subject(ctx)
	err := accesscontext.Error(ctx)

	if len(subject) != 0 {
		event.Str("_subject", subject)
	}

	if err != nil || statusCode >= 300 {
		event.Err(err).Bool("_access_granted", false)
	} else {
		event.Bool("_access_granted", true)
	}

	return event
}

func logTraceData(ctx context.Context, logCtx zerolog.Context) zerolog.Context {
	if traceCtx := tracecontext.Extract(ctx); traceCtx != nil {
		logCtx = logCtx.
			Str("_trace_id", traceCtx.TraceID).
			Str("_span_id", traceCtx.SpanID)

		if len(traceCtx.ParentID) != 0 {
			logCtx = logCtx.Str("_parent_id", traceCtx.ParentID)
		}
	}

	return logCtx
}

func logHeader(req *http.Request, logCtx zerolog.Context, headerName, logKey string) zerolog.Context {
	if headerValue := req.Header.Get(headerName); len(headerValue) != 0 {
		logCtx = logCtx.Str(logKey, headerValue)
	}

	return logCtx
}
