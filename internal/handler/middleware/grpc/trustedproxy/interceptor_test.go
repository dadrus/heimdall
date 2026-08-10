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
	"maps"
	"net"
	"testing"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestInterceptorExecution(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ips        []string
		shouldDrop bool
		warningLog string
	}{
		"bad IP range": {
			ips:        []string{"/128"},
			shouldDrop: true,
			warningLog: "could not be parsed",
		},
		"single IP trusted": {
			ips:        []string{"127.0.0.1"},
			shouldDrop: false,
		},
		"trusted IP range": {
			ips:        []string{"127.0.0.0/24"},
			shouldDrop: false,
		},
		"source in IP range but not trusted IPv4": {
			ips:        []string{"172.0.0.0/0"},
			shouldDrop: false,
			warningLog: "trusted proxies contains insecure",
		},
		"source not in IPv6 range and is not trusted 1": {
			ips:        []string{"::/0"},
			shouldDrop: true,
			warningLog: "trusted proxies contains insecure",
		},
		"source not in IPv6 range and is not trusted 2": {
			ips:        []string{"3209:7473:73ed:a31c:0a08:f214:2434:d5ce/0"},
			shouldDrop: true,
			warningLog: "trusted proxies contains insecure",
		},
		"source not in IPv4 range": {
			ips:        []string{"172.0.0.0/24"},
			shouldDrop: true,
		},
		"empty list": {
			ips:        []string{},
			shouldDrop: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			sendMD := metadata.Pairs(
				"x-forwarded-proto", "https",
				"x-forwarded-host", "foobar.com",
				"x-forwarded-path", "/test",
				"x-forwarded-uri", "/test?foo=bar",
				"x-forwarded-for", "172.17.1.2",
				"x-forwarded-method", "GET",
				"forwarded", "for=172.17.1.2;proto=https",
				"x-foo-bar", "foo",
			)
			sendHeaders := map[string]string{
				"x-forwarded-proto":  "https",
				"x-forwarded-host":   "foobar.com",
				"x-forwarded-path":   "/test",
				"x-forwarded-uri":    "/test?foo=bar",
				"x-forwarded-for":    "172.17.1.2",
				"x-forwarded-method": "GET",
				"forwarded":          "for=172.17.1.2;proto=https",
				"x-foo-bar":          "foo",
			}

			var (
				receivedMD      metadata.MD
				receivedHeaders map[string]string
			)

			tb := &testsupport.TestingLog{TB: t}
			logger := zerolog.New(zerolog.TestWriter{T: tb})

			ctx := metadata.NewIncomingContext(t.Context(), sendMD)
			ctx = peer.NewContext(ctx, &peer.Peer{
				Addr: &net.TCPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 12345,
				},
			})

			req := &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Headers: sendHeaders,
						},
					},
				},
			}

			interceptor := New(logger, tc.ips...)

			// WHEN
			_, err := interceptor(
				ctx,
				req,
				&grpc.UnaryServerInfo{},
				func(ctx context.Context, req any) (any, error) {
					receivedMD, _ = metadata.FromIncomingContext(ctx)

					checkReq := req.(*envoy_auth.CheckRequest)
					receivedHeaders = maps.Clone(
						checkReq.
							GetAttributes().
							GetRequest().
							GetHttp().
							GetHeaders(),
					)

					return &envoy_auth.CheckResponse{}, nil
				},
			)

			// THEN
			require.NoError(t, err)

			if tc.shouldDrop {
				require.Empty(t, receivedMD.Get("X-Forwarded-Proto"))
				require.Empty(t, receivedMD.Get("X-Forwarded-Host"))
				require.Empty(t, receivedMD.Get("X-Forwarded-Path"))
				require.Empty(t, receivedMD.Get("X-Forwarded-Uri"))
				require.Empty(t, receivedMD.Get("X-Forwarded-For"))
				require.Empty(t, receivedMD.Get("X-Forwarded-Method"))
				require.Empty(t, receivedMD.Get("Forwarded"))
				require.Equal(t, []string{"foo"}, receivedMD.Get("X-Foo-Bar"))

				require.Empty(t, receivedHeaders["x-forwarded-proto"])
				require.Empty(t, receivedHeaders["x-forwarded-host"])
				require.Empty(t, receivedHeaders["x-forwarded-path"])
				require.Empty(t, receivedHeaders["x-forwarded-uri"])
				require.Empty(t, receivedHeaders["x-forwarded-for"])
				require.Empty(t, receivedHeaders["x-forwarded-method"])
				require.Empty(t, receivedHeaders["forwarded"])
				require.Equal(t, "foo", receivedHeaders["x-foo-bar"])
			} else {
				require.Equal(t, sendMD.Get("X-Forwarded-Proto"), receivedMD.Get("X-Forwarded-Proto"))
				require.Equal(t, sendMD.Get("X-Forwarded-Host"), receivedMD.Get("X-Forwarded-Host"))
				require.Equal(t, sendMD.Get("X-Forwarded-Path"), receivedMD.Get("X-Forwarded-Path"))
				require.Equal(t, sendMD.Get("X-Forwarded-Uri"), receivedMD.Get("X-Forwarded-Uri"))
				require.Equal(t, sendMD.Get("X-Forwarded-For"), receivedMD.Get("X-Forwarded-For"))
				require.Equal(t, sendMD.Get("X-Forwarded-Method"), receivedMD.Get("X-Forwarded-Method"))
				require.Equal(t, sendMD.Get("Forwarded"), receivedMD.Get("Forwarded"))
				require.Equal(t, sendMD.Get("X-Foo-Bar"), receivedMD.Get("X-Foo-Bar"))

				require.Equal(t, sendHeaders["x-forwarded-proto"], receivedHeaders["x-forwarded-proto"])
				require.Equal(t, sendHeaders["x-forwarded-host"], receivedHeaders["x-forwarded-host"])
				require.Equal(t, sendHeaders["x-forwarded-path"], receivedHeaders["x-forwarded-path"])
				require.Equal(t, sendHeaders["x-forwarded-uri"], receivedHeaders["x-forwarded-uri"])
				require.Equal(t, sendHeaders["x-forwarded-for"], receivedHeaders["x-forwarded-for"])
				require.Equal(t, sendHeaders["x-forwarded-method"], receivedHeaders["x-forwarded-method"])
				require.Equal(t, sendHeaders["forwarded"], receivedHeaders["forwarded"])
				require.Equal(t, sendHeaders["x-foo-bar"], receivedHeaders["x-foo-bar"])
			}

			logs := tb.CollectedLog()
			if len(logs) != 0 {
				require.NotEmpty(t, tc.warningLog, "logs contain warnings, but no warnings are expected")
				assert.Contains(t, logs, tc.warningLog)
			}
		})
	}
}
