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
	log := logger.Level(zerolog.InfoLevel).With().Logger()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			start := time.Now()
			ctx := accesscontext.New(req.Context())
			req = req.WithContext(ctx)
			host := httpx.IPFromHostPort(req.RemoteAddr)
			traceCtx := tracecontext.Extract(ctx)

			logEvt := logCommonData(log.Info(), start, host, req, &traceCtx)
			logEvt.Msg("TX started")

			metrics := httpsnoop.CaptureMetrics(next, rw, req)

			logEvt = logCommonData(log.Info(), start, host, req, &traceCtx)
			logAccessStatus(ctx, logEvt, metrics.Code).
				Int64("_body_bytes_sent", metrics.Written).
				Int("_http_status_code", metrics.Code).
				Int64("_tx_duration_ms", time.Since(start).Milliseconds()).
				Msg("TX finished")
		})
	}
}

func logCommonData(
	logEvt *zerolog.Event,
	start time.Time,
	host string,
	req *http.Request,
	traceCtx *tracecontext.TraceContext,
) *zerolog.Event {
	logEvt = logEvt.
		Int64("_tx_start", start.Unix()).
		Str("_client_ip", host).
		Str("_http_method", req.Method).
		Str("_http_path", req.URL.Path).
		Str("_http_user_agent", req.Header.Get("User-Agent")).
		Str("_http_host", req.Host).
		Str("_http_scheme", x.IfThenElse(req.TLS != nil, "https", "http"))

	logEvt = logTraceData(traceCtx, logEvt)
	logEvt = logHeader(req, logEvt, "X-Forwarded-Method", "_http_x_forwarded_method")
	logEvt = logHeader(req, logEvt, "X-Forwarded-Proto", "_http_x_forwarded_proto")
	logEvt = logHeader(req, logEvt, "X-Forwarded-Host", "_http_x_forwarded_host")
	logEvt = logHeader(req, logEvt, "X-Forwarded-Uri", "_http_x_forwarded_uri")
	logEvt = logHeader(req, logEvt, "X-Forwarded-For", "_http_x_forwarded_for")
	logEvt = logHeader(req, logEvt, "Forwarded", "_http_forwarded")

	return logEvt
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

func logTraceData(ctx *tracecontext.TraceContext, logEvt *zerolog.Event) *zerolog.Event {
	if len(ctx.TraceID) != 0 {
		logEvt = logEvt.
			Str("_trace_id", ctx.TraceID).
			Str("_span_id", ctx.SpanID)

		if len(ctx.ParentID) != 0 {
			logEvt = logEvt.Str("_parent_id", ctx.ParentID)
		}
	}

	return logEvt
}

func logHeader(req *http.Request, logEvt *zerolog.Event, headerName, logKey string) *zerolog.Event {
	if headerValue := req.Header.Get(headerName); len(headerValue) != 0 {
		logEvt = logEvt.Str(logKey, headerValue)
	}

	return logEvt
}
