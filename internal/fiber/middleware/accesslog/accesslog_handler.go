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
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/accesscontext"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/tracecontext"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

func New(logger zerolog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		c.SetUserContext(accesscontext.New(c.UserContext()))

		logCtx := logger.Level(zerolog.InfoLevel).With().
			Int64("_tx_start", start.Unix()).
			Str("_client_ip", c.IP()).
			Str("_http_method", c.Method()).
			Str("_http_path", c.Path()).
			Str("_http_user_agent", c.Get("User-Agent")).
			Str("_http_host", stringx.ToString(c.Request().URI().Host())).
			Str("_http_scheme", stringx.ToString(c.Request().URI().Scheme()))
		logCtx = logTraceData(c.UserContext(), logCtx)

		if c.IsProxyTrusted() {
			logCtx = logHeader(c, logCtx, "X-Forwarded-Method", "_http_x_forwarded_method")
			logCtx = logHeader(c, logCtx, "X-Forwarded-Proto", "_http_x_forwarded_proto")
			logCtx = logHeader(c, logCtx, "X-Forwarded-Host", "_http_x_forwarded_host")
			logCtx = logHeader(c, logCtx, "X-Forwarded-Path", "_http_x_forwarded_path")
			logCtx = logHeader(c, logCtx, "X-Forwarded-Uri", "_http_x_forwarded_uri")
			logCtx = logHeader(c, logCtx, "X-Forwarded-For", "_http_x_forwarded_for")
			logCtx = logHeader(c, logCtx, "Forwarded", "_http_forwarded")
		}

		accLog := logCtx.Logger()
		accLog.Info().Msg("TX started")

		err := c.Next()

		logAccessStatus(c.UserContext(), accLog.Info(), err).
			Int("_body_bytes_sent", len(c.Response().Body())).
			Int("_http_status_code", c.Response().StatusCode()).
			Int64("_tx_duration_ms", time.Until(start).Milliseconds()).
			Msg("TX finished")

		return err
	}
}

func logAccessStatus(ctx context.Context, event *zerolog.Event, err error) *zerolog.Event {
	subject := accesscontext.Subject(ctx)
	accessErr := accesscontext.Error(ctx)

	switch {
	case err != nil:
		if len(subject) != 0 {
			event.Str("_subject", subject)
		}

		event.Err(err).Bool("_access_granted", false)
	case accessErr != nil:
		if len(subject) != 0 {
			event.Str("_subject", subject)
		}

		event.Err(accessErr).Bool("_access_granted", false)
	default:
		event.Str("_subject", subject).Bool("_access_granted", true)
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

func logHeader(c *fiber.Ctx, logCtx zerolog.Context, headerName, logKey string) zerolog.Context {
	if headerValue := c.Get(headerName); len(headerValue) != 0 {
		logCtx = logCtx.Str(logKey, headerValue)
	}

	return logCtx
}
