// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/accesscontext"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/tracecontext"
)

func New(logger zerolog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		traceCtx := tracecontext.Extract(c.UserContext())
		c.SetUserContext(accesscontext.New(c.UserContext()))

		accLog := createAccessLogger(c, logger, start, traceCtx)
		accLog.Info().Msg("TX started")

		err := c.Next()

		createAccessLogFinalizationEvent(c, accLog, err, start, traceCtx).Msg("TX finished")

		return err
	}
}

func createAccessLogger(
	c *fiber.Ctx,
	logger zerolog.Logger,
	start time.Time,
	traceCtx *tracecontext.TraceContext,
) zerolog.Logger {
	startTime := start.Unix()

	logCtx := logger.Level(zerolog.InfoLevel).With().
		Int64("_tx_start", startTime).
		Str("_client_ip", c.IP()).
		Str("_http_method", c.Method()).
		Str("_http_path", c.Path()).
		Str("_http_user_agent", c.Get("User-Agent")).
		Str("_http_host", string(c.Request().URI().Host())).
		Str("_http_scheme", string(c.Request().URI().Scheme()))

	if traceCtx != nil {
		logCtx = logCtx.
			Str("_trace_id", traceCtx.TraceID).
			Str("_span_id", traceCtx.SpanID)

		if len(traceCtx.ParentID) != 0 {
			logCtx = logCtx.Str("_parent_id", traceCtx.ParentID)
		}
	}

	if c.IsProxyTrusted() { // nolint: nestif
		if headerValue := c.Get("X-Forwarded-Proto"); len(headerValue) != 0 {
			logCtx = logCtx.Str("_http_x_forwarded_proto", headerValue)
		}

		if headerValue := c.Get("X-Forwarded-Host"); len(headerValue) != 0 {
			logCtx = logCtx.Str("_http_x_forwarded_host", headerValue)
		}

		if headerValue := c.Get("X-Forwarded-Path"); len(headerValue) != 0 {
			logCtx = logCtx.Str("_http_x_forwarded_path", headerValue)
		}

		if headerValue := c.Get("X-Forwarded-Uri"); len(headerValue) != 0 {
			logCtx = logCtx.Str("_http_x_forwarded_uri", headerValue)
		}

		if headerValue := c.Get("X-Forwarded-For"); len(headerValue) != 0 {
			logCtx = logCtx.Str("_http_x_forwarded_for", headerValue)
		}

		if headerValue := c.Get("Forwarded"); len(headerValue) != 0 {
			logCtx = logCtx.Str("_http_forwarded", headerValue)
		}
	}

	return logCtx.Logger()
}

func createAccessLogFinalizationEvent(
	c *fiber.Ctx,
	accessLogger zerolog.Logger,
	err error,
	start time.Time,
	traceCtx *tracecontext.TraceContext,
) *zerolog.Event {
	end := time.Now()
	duration := end.Sub(start)
	subject := accesscontext.Subject(c.UserContext())
	accessErr := accesscontext.Error(c.UserContext())

	event := accessLogger.Info().
		Int("_body_bytes_sent", len(c.Response().Body())).
		Int("_http_status_code", c.Response().StatusCode()).
		Int64("_tx_duration_ms", duration.Milliseconds())

	if traceCtx != nil {
		event = event.
			Str("_trace_id", traceCtx.TraceID).
			Str("_span_id", traceCtx.SpanID)

		if len(traceCtx.ParentID) != 0 {
			event = event.Str("_parent_id", traceCtx.ParentID)
		}
	}

	switch {
	case err != nil:
		if len(subject) != 0 {
			event = event.Str("_subject", subject)
		}

		event = event.Err(err).Bool("_access_granted", false)
	case accessErr != nil:
		if len(subject) != 0 {
			event = event.Str("_subject", subject)
		}

		event = event.Err(accessErr).Bool("_access_granted", false)
	default:
		event = event.Str("_subject", subject).Bool("_access_granted", true)
	}

	return event
}
