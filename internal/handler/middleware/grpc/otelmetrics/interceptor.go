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

package otelmetrics

import (
	"context"
	"net"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/dadrus/heimdall/internal/x/httpx"
)

const (
	instrumentationName = "github.com/dadrus/heimdall/internal/handler/middleware/grpc/otelmetrics"

	requestsActive = "rpc.server.active_requests"
)

type ServerInterceptor interface {
	UnaryServerInterceptor() grpc.UnaryServerInterceptor
	StreamServerInterceptor() grpc.StreamServerInterceptor
}

type metricsInterceptor struct {
	activeRequests metric.Int64UpDownCounter
	attributes     []attribute.KeyValue
	pool           sync.Pool
}

func (h *metricsInterceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return h.observeUnaryRequest
}

func (h *metricsInterceptor) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return h.observeStreamRequest
}

func New(opts ...Option) ServerInterceptor {
	conf := newConfig(opts...)

	meter := conf.provider.Meter(instrumentationName)

	activeRequestsMeasure, err := meter.Int64UpDownCounter(
		requestsActive,
		metric.WithDescription("Number of active RPC server requests."),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		panic(err)
	}

	base := make([]attribute.KeyValue, 0, len(conf.attributes)+3)
	base = append(base, conf.attributes...)
	base = append(base, conf.subsystem)

	host, port := httpx.HostPort(conf.server)
	if host == "" {
		host = "127.0.0.1"
	}

	base = append(base, semconv.ServerAddress(host), semconv.ServerPort(port))

	handler := &metricsInterceptor{
		activeRequests: activeRequestsMeasure,
		attributes:     base,
		pool: sync.Pool{
			New: func() any {
				attrs := make([]attribute.KeyValue, 0, len(base)+5)

				return &attrs
			},
		},
	}

	return handler
}

func (h *metricsInterceptor) observeUnaryRequest(
	ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	pkv := h.pool.Get().(*[]attribute.KeyValue) //nolint: forcetypeassert
	attrs := *pkv

	defer func() {
		*pkv = attrs[:0]

		h.pool.Put(pkv)
	}()

	attrs = append(attrs, h.attributes...)
	attrs = addRequestAttributes(attrs, info.FullMethod, peerFromCtx(ctx))
	opts := metric.WithAttributeSet(attribute.NewSet(attrs...))

	h.activeRequests.Add(ctx, 1, opts)
	defer h.activeRequests.Add(ctx, -1, opts)

	return handler(ctx, req)
}

func (h *metricsInterceptor) observeStreamRequest(
	srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	pkv := h.pool.Get().(*[]attribute.KeyValue) //nolint: forcetypeassert
	attrs := *pkv

	defer func() {
		*pkv = attrs[:0]

		h.pool.Put(pkv)
	}()

	ctx := stream.Context()

	attrs = append(attrs, h.attributes...)
	attrs = addRequestAttributes(attrs, info.FullMethod, peerFromCtx(ctx))
	opts := metric.WithAttributeSet(attribute.NewSet(attrs...))

	h.activeRequests.Add(ctx, 1, opts)
	defer h.activeRequests.Add(ctx, -1, opts)

	return handler(srv, stream)
}

func peerFromCtx(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}

	return p.Addr.String()
}

func parseFullMethod(fullMethod string) (string, string) {
	if !strings.HasPrefix(fullMethod, "/") {
		// Invalid format, does not follow `/package.service/method`.
		return "", ""
	}

	name := fullMethod[1:]
	pos := strings.LastIndexByte(name, '/')

	if pos < 0 {
		// Invalid format, does not follow `/package.service/method`.
		return "", ""
	}

	return name[:pos], name[pos+1:]
}

func addRequestAttributes(attrs []attribute.KeyValue, fullMethod, peerAddress string) []attribute.KeyValue {
	service, method := parseFullMethod(fullMethod)
	host, port := httpx.HostPort(peerAddress)

	if host == "" {
		host = "127.0.0.1"
	}

	attrs = append(attrs, semconv.RPCSystemGRPC)

	if len(service) != 0 {
		attrs = append(attrs, semconv.RPCService(service))
	}

	if len(method) != 0 {
		attrs = append(attrs, semconv.RPCMethod(method))
	}

	if ip := net.ParseIP(host); ip != nil {
		attrs = append(attrs, semconv.NetworkPeerAddress(host), semconv.NetworkPeerPort(port))
	} else {
		attrs = append(attrs, semconv.ClientAddress(host), semconv.ClientPort(port))
	}

	return attrs
}
