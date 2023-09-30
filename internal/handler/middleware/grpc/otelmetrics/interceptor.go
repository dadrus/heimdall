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
	"slices"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

const (
	instrumentationName = "github.com/dadrus/heimdall/internal/handler/middleware/grpc/otelmetrics"

	requestsActive = "grpc.server.active_requests"
)

type ServerInterceptor interface {
	UnaryServerInterceptor() grpc.UnaryServerInterceptor
	StreamServerInterceptor() grpc.StreamServerInterceptor
}

type metricsInterceptor struct {
	activeRequests metric.Float64UpDownCounter
	attributes     []attribute.KeyValue
	server         string
	subsystem      attribute.KeyValue
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

	activeRequests, err := meter.Float64UpDownCounter(
		requestsActive,
		metric.WithDescription("Measures the number of concurrent GRPC requests that are currently in-flight."),
		metric.WithUnit("1"),
	)
	if err != nil {
		panic(err)
	}

	handler := &metricsInterceptor{
		activeRequests: activeRequests,
		attributes:     conf.attributes,
		server:         conf.server,
		subsystem:      conf.subsystem,
	}

	return handler
}

func (h *metricsInterceptor) observeUnaryRequest(
	ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	attr := spanInfo(info.FullMethod, peerFromCtx(ctx))

	attributes := append(slices.Clone(h.attributes), h.subsystem)
	attributes = append(attributes, attr...)

	opt := metric.WithAttributes(attributes...)

	h.activeRequests.Add(ctx, 1, opt)
	defer h.activeRequests.Add(ctx, -1, opt)

	return handler(ctx, req)
}

func (h *metricsInterceptor) observeStreamRequest(
	srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	ctx := stream.Context()
	attr := spanInfo(info.FullMethod, peerFromCtx(ctx))

	attributes := append(slices.Clone(h.attributes), h.subsystem)
	attributes = append(attributes, attr...)

	opt := metric.WithAttributes(attributes...)

	h.activeRequests.Add(ctx, 1, opt)
	defer h.activeRequests.Add(ctx, -1, opt)

	return handler(srv, stream)
}

func peerFromCtx(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}

	return p.Addr.String()
}

func peerAttr(addr string) []attribute.KeyValue {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}

	if host == "" {
		host = "127.0.0.1"
	}

	portVal, err := strconv.Atoi(port)
	if err != nil {
		return nil
	}

	var attr []attribute.KeyValue
	if ip := net.ParseIP(host); ip != nil {
		attr = []attribute.KeyValue{
			semconv.NetSockPeerAddr(host),
			semconv.NetSockPeerPort(portVal),
		}
	} else {
		attr = []attribute.KeyValue{
			semconv.NetPeerName(host),
			semconv.NetPeerPort(portVal),
		}
	}

	return attr
}

func parseFullMethod(fullMethod string) (string, []attribute.KeyValue) {
	if !strings.HasPrefix(fullMethod, "/") {
		// Invalid format, does not follow `/package.service/method`.
		return fullMethod, nil
	}

	name := fullMethod[1:]
	pos := strings.LastIndex(name, "/")

	if pos < 0 {
		// Invalid format, does not follow `/package.service/method`.
		return name, nil
	}

	service, method := name[:pos], name[pos+1:]

	var attrs []attribute.KeyValue
	if service != "" {
		attrs = append(attrs, semconv.RPCService(service))
	}

	if method != "" {
		attrs = append(attrs, semconv.RPCMethod(method))
	}

	return name, attrs
}

func spanInfo(fullMethod, peerAddress string) []attribute.KeyValue {
	_, mAttrs := parseFullMethod(fullMethod)
	peerAttrs := peerAttr(peerAddress)

	attrs := make([]attribute.KeyValue, 0, 1+len(mAttrs)+len(peerAttrs))
	attrs = append(attrs, semconv.RPCSystemGRPC)
	attrs = append(attrs, mAttrs...)
	attrs = append(attrs, peerAttrs...)

	return attrs
}
