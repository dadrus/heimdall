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
	Unary() grpc.UnaryServerInterceptor
	Stream() grpc.StreamServerInterceptor
}

func New(logger zerolog.Logger) ServerInterceptor {
	return &accessLogInterceptor{l: logger}
}

type accessLogInterceptor struct {
	l zerolog.Logger
}

func (i *accessLogInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start, accLog := i.startTransaction(ctx, info.FullMethod)

		ctx = accesscontext.New(ctx)
		resp, err := handler(ctx, req)

		i.finalizeTransaction(ctx, accLog, start, err)

		return resp, err
	}
}

func (i *accessLogInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) error {
		ctx := stream.Context()
		start, accLog := i.startTransaction(ctx, info.FullMethod)

		ctx = accesscontext.New(ctx)
		err := handler(srv, stream)

		i.finalizeTransaction(ctx, accLog, start, err)

		return err
	}
}

func (i *accessLogInterceptor) startTransaction(ctx context.Context, fullMethod string) (time.Time, zerolog.Logger) {
	start := time.Now()
	requestMetadata, _ := metadata.FromIncomingContext(ctx)

	logCtx := i.l.Level(zerolog.InfoLevel).With().
		Int64("_tx_start", start.Unix()).
		Str("_client_ip", peerFromCtx(ctx)).
		Str("_grpc_method", fullMethod)

	logCtx = logTraceData(ctx, logCtx)
	logCtx = logMetaData(logCtx, requestMetadata, "x-forwarded-for", "_x_forwarded_for")
	logCtx = logMetaData(logCtx, requestMetadata, "forwarded", "_forwarded")

	accLog := logCtx.Logger()
	accLog.Info().Msg("TX started")

	return start, accLog
}

func (i *accessLogInterceptor) finalizeTransaction(
	ctx context.Context, accLog zerolog.Logger, start time.Time, err error,
) {
	// grpc errors are only used to signal unusual conditions
	// in all other cases the error is anyway embedded into the envoy CheckResponse object
	// so that on the grpc level no error is returned
	grpcStatus, _ := status.FromError(err)

	logAccessStatus(ctx, accLog.Info(), err).
		Uint32("_grpc_status_code", uint32(grpcStatus.Code())).
		Int64("_tx_duration_ms", time.Until(start).Milliseconds()).
		Msg("TX finished")
}

func logAccessStatus(ctx context.Context, event *zerolog.Event, err error) *zerolog.Event {
	subject := accesscontext.Subject(ctx)
	accessErr := accesscontext.Error(ctx)
	dict := zerolog.Dict()

	if len(subject) != 0 {
		for _, v := range subject {
			dict = dict.Str("id", v.ID)
		}
	}

	switch {
	case err != nil:
		if len(subject) != 0 {
			event.Dict("_subject", dict)
		}

		event.Err(err).Bool("_access_granted", false)
	case accessErr != nil:
		if len(subject) != 0 {
			event.Dict("_subject", dict)
		}

		event.Err(accessErr).Bool("_access_granted", false)
	default:
		event.Dict("_subject", dict).Bool("_access_granted", true)
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

func logMetaData(logCtx zerolog.Context, rmd metadata.MD, mdKey, logKey string) zerolog.Context {
	if len(rmd) == 0 {
		return logCtx
	}

	if headerValue := rmd.Get(mdKey); len(headerValue) != 0 {
		logCtx = logCtx.Str(logKey, strings.Join(headerValue, ","))
	}

	return logCtx
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
