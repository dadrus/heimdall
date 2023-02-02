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
	"strings"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/dadrus/heimdall/internal/accesscontext"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/tracecontext"
)

func New(logger zerolog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		requestMetadata, _ := metadata.FromIncomingContext(ctx)

		logCtx := logger.Level(zerolog.InfoLevel).With().
			Int64("_tx_start", start.Unix()).
			Str("_peer", peerFromCtx(ctx)).
			Str("_request", info.FullMethod)

		logCtx = logTraceData(ctx, logCtx)
		logCtx = md(logCtx, requestMetadata, "x-forwarded-for", "_x_forwarded_for")
		logCtx = md(logCtx, requestMetadata, "forwarded", "_forwarded")

		accLog := logCtx.Logger()
		accLog.Info().Msg("TX started")

		ctx = accesscontext.New(ctx)
		res, err := handler(ctx, req)

		logAccessStatus(ctx, accLog.Info(), err).
			Int64("_tx_duration_ms", time.Until(start).Milliseconds()).
			Msg("TX finished")

		return res, err
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

func md(logCtx zerolog.Context, rmd metadata.MD, mdKey, logKey string) zerolog.Context {
	if headerValue := rmd.Get(mdKey); len(headerValue) != 0 {
		logCtx = logCtx.Str(logKey, strings.Join(headerValue, ","))
	}

	return logCtx
}

func peerFromCtx(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}

	return p.Addr.String()
}
