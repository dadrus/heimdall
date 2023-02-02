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

package logger

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x/opentelemetry/tracecontext"
)

func New(logger zerolog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()

		c.SetUserContext(withTraceData(ctx, logger.With()).Logger().WithContext(ctx))

		return c.Next()
	}
}

func withTraceData(ctx context.Context, logCtx zerolog.Context) zerolog.Context {
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
