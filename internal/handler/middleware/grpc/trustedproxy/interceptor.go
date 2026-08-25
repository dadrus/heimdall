// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package trustedproxy

import (
	"context"
	"net"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/dadrus/heimdall/internal/handler/middleware/trustedproxy"
)

func New(logger zerolog.Logger, proxies ...string) grpc.UnaryServerInterceptor {
	matcher := trustedproxy.NewMatcher(logger, proxies...)

	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if !matcher.Contains(peerIP(ctx)) {
			ctx = sanitizeMetadata(ctx)
			sanitizeRequest(req)
		}

		return handler(ctx, req)
	}
}

func peerIP(ctx context.Context) net.IP {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}

	if addr, ok := peerInfo.Addr.(*net.TCPAddr); ok {
		return addr.IP
	}

	host, _, err := net.SplitHostPort(peerInfo.Addr.String())
	if err != nil {
		return net.ParseIP(peerInfo.Addr.String())
	}

	return net.ParseIP(host)
}

func sanitizeMetadata(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}

	trustedproxy.RemoveForwardingHeaders(md.Delete)

	return metadata.NewIncomingContext(ctx, md)
}

func sanitizeRequest(req any) {
	checkReq, ok := req.(*envoy_auth.CheckRequest)
	if !ok {
		return
	}

	headers := checkReq.
		GetAttributes().
		GetRequest().
		GetHttp().
		GetHeaders()

	for key := range headers {
		if trustedproxy.IsForwardingHeader(key) {
			delete(headers, key)
		}
	}
}
