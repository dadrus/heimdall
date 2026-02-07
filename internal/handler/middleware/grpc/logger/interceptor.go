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
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/dadrus/heimdall/internal/accesscontext"
	"github.com/dadrus/heimdall/internal/x/opentelemetry/tracecontext"
)

type ServerInterceptor interface {
	UnaryServerInterceptor() grpc.UnaryServerInterceptor
	StreamServerInterceptor() grpc.StreamServerInterceptor
}

func New(logger zerolog.Logger) ServerInterceptor {
	return &logInterceptor{
		logger:       logger,
		accessLogger: logger.Level(zerolog.InfoLevel).With().Logger(),
	}
}

type logInterceptor struct {
	logger       zerolog.Logger
	accessLogger zerolog.Logger
}

func (li *logInterceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		requestMD, _ := metadata.FromIncomingContext(ctx)
		peerAddr := peerFromCtx(ctx)
		traceCtx := tracecontext.Extract(ctx)
		ctx = accesscontext.New(ctx)

		logEvt := logCommonData(li.accessLogger.Info(), start, peerAddr, info.FullMethod, traceCtx, requestMD)
		logEvt.Msg("TX started")

		resp, err := handler(withTraceData(li.logger.With(), &traceCtx).Logger().WithContext(ctx), req)
		grpcStatus, _ := status.FromError(err)

		logEvt = logCommonData(li.accessLogger.Info(), start, peerAddr, info.FullMethod, traceCtx, requestMD)
		logEvt = logAccessStatus(ctx, logEvt, err).
			Uint32("_grpc_status_code", uint32(grpcStatus.Code())).
			Int64("_tx_duration_ms", time.Since(start).Milliseconds())
		logEvt.Msg("TX finished")

		return resp, err
	}
}

func (li *logInterceptor) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) error {
		start := time.Now()
		ctx := stream.Context()
		requestMD, _ := metadata.FromIncomingContext(ctx)
		peerAddr := peerFromCtx(ctx)
		traceCtx := tracecontext.Extract(ctx)
		ctx = accesscontext.New(ctx)

		logEvt := logCommonData(li.accessLogger.Info(), start, peerAddr, info.FullMethod, traceCtx, requestMD)
		logEvt.Msg("TX started")

		err := handler(srv, stream)
		grpcStatus, _ := status.FromError(err)

		logEvt = logCommonData(li.accessLogger.Info(), start, peerAddr, info.FullMethod, traceCtx, requestMD)
		logEvt = logAccessStatus(ctx, logEvt, err).
			Uint32("_grpc_status_code", uint32(grpcStatus.Code())).
			Int64("_tx_duration_ms", time.Since(start).Milliseconds())
		logEvt.Msg("TX finished")

		return err
	}
}

func withTraceData(logCtx zerolog.Context, traceCtx *tracecontext.TraceContext) zerolog.Context {
	if len(traceCtx.TraceID) != 0 {
		logCtx = logCtx.
			Str("_trace_id", traceCtx.TraceID).
			Str("_span_id", traceCtx.SpanID)

		if len(traceCtx.ParentID) != 0 {
			logCtx = logCtx.Str("_parent_id", traceCtx.ParentID)
		}
	}

	return logCtx
}

func logCommonData(
	logEvt *zerolog.Event,
	start time.Time,
	peerAddr string,
	fullMethod string,
	traceCtx tracecontext.TraceContext,
	requestMD metadata.MD,
) *zerolog.Event {
	logEvt.
		Int64("_tx_start", start.Unix()).
		Str("_client_ip", peerAddr).
		Str("_grpc_method", fullMethod)
	logEvt = logTraceData(&traceCtx, logEvt)
	logEvt = logMetaData(logEvt, requestMD, "x-forwarded-for", "_x_forwarded_for")
	logEvt = logMetaData(logEvt, requestMD, "forwarded", "_forwarded")

	return logEvt
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

func logTraceData(traceCtx *tracecontext.TraceContext, logEvt *zerolog.Event) *zerolog.Event {
	if len(traceCtx.TraceID) != 0 {
		logEvt = logEvt.
			Str("_trace_id", traceCtx.TraceID).
			Str("_span_id", traceCtx.SpanID)

		if len(traceCtx.ParentID) != 0 {
			logEvt = logEvt.Str("_parent_id", traceCtx.ParentID)
		}
	}

	return logEvt
}

func logMetaData(logEvt *zerolog.Event, rmd metadata.MD, mdKey, logKey string) *zerolog.Event {
	if len(rmd) == 0 {
		return logEvt
	}

	if headerValue := rmd.Get(mdKey); len(headerValue) != 0 {
		logEvt = logEvt.Str(logKey, strings.Join(headerValue, ","))
	}

	return logEvt
}

func peerFromCtx(ctx context.Context) string {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}

	if tcpAddr, ok := peerInfo.Addr.(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}

	return peerInfo.Addr.String()
}
