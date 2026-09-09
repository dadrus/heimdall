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

package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/inhies/go-bytesize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
)

type closeTrackingBody struct {
	closed bool
}

func (*closeTrackingBody) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (b *closeTrackingBody) Close() error {
	b.closed = true

	return nil
}

func TestNewProfileRoundTripper(t *testing.T) {
	t.Parallel()

	// GIVEN
	cfg := config.ServeConfig{}
	cfg.Upstream.Connections.DialTimeout = 11 * time.Second
	cfg.Upstream.Connections.TLSHandshakeTimeout = 12 * time.Second
	cfg.Upstream.Connections.IdleTimeout = 13 * time.Second
	cfg.Upstream.Connections.MaxIdle = 17
	cfg.Upstream.Connections.MaxIdlePerHost = 19
	cfg.Upstream.Connections.MaxPerHost = 23
	cfg.Upstream.Requests.ExpectContinueTimeout = 14 * time.Second
	cfg.Upstream.Responses.Headers.ReadTimeout = 15 * time.Second
	cfg.Upstream.Responses.Headers.MaxSize = 42 * bytesize.KB

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// WHEN
	rt := newProfileRoundTripper(cfg, tlsCfg)

	// THEN
	require.NotNil(t, rt)
	require.NotNil(t, rt.normal)
	require.NotNil(t, rt.http1Only)
	require.NotNil(t, rt.http2Required)

	assert.NotSame(t, rt.normal, rt.http1Only)
	assert.NotSame(t, rt.normal, rt.http2Required)
	assert.NotSame(t, rt.http1Only, rt.http2Required)

	assertTransportConfiguration(t, rt.normal, cfg, tlsCfg)
	assertTransportConfiguration(t, rt.http1Only, cfg, tlsCfg)
	assertTransportConfiguration(t, rt.http2Required, cfg, tlsCfg)

	assertTransportProtocols(t, rt.normal, true, true, false)
	assertTransportProtocols(t, rt.http1Only, true, false, false)
	assertTransportProtocols(t, rt.http2Required, false, true, true)

	assert.False(t, rt.normal.ForceAttemptHTTP2)
	assert.False(t, rt.http1Only.ForceAttemptHTTP2)
	assert.False(t, rt.http2Required.ForceAttemptHTTP2)

	assert.NotSame(t, tlsCfg, rt.normal.TLSClientConfig)
	assert.NotSame(t, tlsCfg, rt.http1Only.TLSClientConfig)
	assert.NotSame(t, tlsCfg, rt.http2Required.TLSClientConfig)
	assert.NotSame(t, rt.normal.TLSClientConfig, rt.http1Only.TLSClientConfig)
	assert.NotSame(t, rt.normal.TLSClientConfig, rt.http2Required.TLSClientConfig)
	assert.NotSame(t, rt.http1Only.TLSClientConfig, rt.http2Required.TLSClientConfig)
}

func TestProfileRoundTripperTransportFor(t *testing.T) {
	t.Parallel()

	rt := &profileRoundTripper{
		normal:        new(http.Transport),
		http1Only:     new(http.Transport),
		http2Required: new(http.Transport),
	}

	for uc, tc := range map[string]struct {
		scheme          upstreamScheme
		rawScheme       string
		nativeGRPC      bool
		upgrade         bool
		expectedProfile transportProfile
		expectedErr     error
	}{
		"ordinary http request uses normal profile": {
			scheme:          upstreamSchemeHTTP,
			rawScheme:       "http",
			expectedProfile: transportProfileNormal,
		},
		"ordinary https request uses normal profile": {
			scheme:          upstreamSchemeHTTPS,
			rawScheme:       "https",
			expectedProfile: transportProfileNormal,
		},
		"http upgrade request uses HTTP/1-only profile": {
			scheme:          upstreamSchemeHTTP,
			rawScheme:       "http",
			upgrade:         true,
			expectedProfile: transportProfileHTTP1Only,
		},
		"https upgrade request uses HTTP/1-only profile": {
			scheme:          upstreamSchemeHTTPS,
			rawScheme:       "https",
			upgrade:         true,
			expectedProfile: transportProfileHTTP1Only,
		},
		"h2c request uses HTTP/2-required profile": {
			scheme:          upstreamSchemeH2C,
			rawScheme:       "h2c",
			expectedProfile: transportProfileHTTP2Required,
		},
		"native gRPC https request uses HTTP/2-required profile": {
			scheme:          upstreamSchemeHTTPS,
			rawScheme:       "https",
			nativeGRPC:      true,
			expectedProfile: transportProfileHTTP2Required,
		},
		"native gRPC h2c request uses HTTP/2-required profile": {
			scheme:          upstreamSchemeH2C,
			rawScheme:       "h2c",
			nativeGRPC:      true,
			expectedProfile: transportProfileHTTP2Required,
		},
		"native gRPC http request is rejected": {
			scheme:      upstreamSchemeHTTP,
			rawScheme:   "http",
			nativeGRPC:  true,
			expectedErr: errNativeGRPCOverHTTP,
		},
		"h2c upgrade request is rejected": {
			scheme:      upstreamSchemeH2C,
			rawScheme:   "h2c",
			upgrade:     true,
			expectedErr: errUpgradeOverH2C,
		},
		"unsupported upstream scheme is rejected": {
			scheme:      upstreamSchemeUnknown,
			rawScheme:   "ftp",
			expectedErr: errUnsupportedUpstreamScheme,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			rc := &requestContext{
				routingURL: url.URL{
					Scheme: tc.rawScheme,
				},
				upstreamScheme: tc.scheme,
				nativeGRPC:     tc.nativeGRPC,
				upgrade:        tc.upgrade,
			}

			// WHEN
			transport, err := rt.transportFor(rc)

			// THEN
			if tc.expectedErr != nil {
				require.ErrorIs(t, err, tc.expectedErr)
				assert.Nil(t, transport)

				return
			}

			require.NoError(t, err)

			switch tc.expectedProfile {
			case transportProfileHTTP1Only:
				assert.Same(t, rt.http1Only, transport)
			case transportProfileHTTP2Required:
				assert.Same(t, rt.http2Required, transport)
			default:
				assert.Same(t, rt.normal, transport)
			}
		})
	}
}

func TestProfileRoundTripperClosesRequestBodyOnSelectionError(t *testing.T) {
	t.Parallel()

	// GIVEN
	body := new(closeTrackingBody)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://upstream.local/test", body)
	require.NoError(t, err)

	rc := &requestContext{
		routingURL: url.URL{
			Scheme: "http",
		},
		upstreamScheme: upstreamSchemeHTTP,
		nativeGRPC:     true,
	}
	invocation := &proxyInvocation{request: rc}
	req = req.WithContext(context.WithValue(req.Context(), proxyInvocationKey{}, invocation))

	rt := &profileRoundTripper{}

	// WHEN
	resp, err := rt.RoundTrip(req) //nolint:bodyclose

	// THEN
	require.ErrorIs(t, err, errNativeGRPCOverHTTP)
	assert.Nil(t, resp)
	assert.True(t, body.closed)
}

func TestIsUpgradeRequest(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		headers  http.Header
		expected bool
	}{
		"upgrade connection option and upgrade header are present": {
			headers: http.Header{
				"Connection": []string{"keep-alive, Upgrade"},
				"Upgrade":    []string{"websocket"},
			},
			expected: true,
		},
		"upgrade connection option is present multiple times": {
			headers: http.Header{
				"Connection": []string{"keep-alive", "upgrade"},
				"Upgrade":    []string{"websocket"},
			},
			expected: true,
		},
		"upgrade header is missing": {
			headers: http.Header{
				"Connection": []string{"Upgrade"},
			},
			expected: false,
		},
		"upgrade connection option is missing": {
			headers: http.Header{
				"Connection": []string{"keep-alive"},
				"Upgrade":    []string{"websocket"},
			},
			expected: false,
		},
		"connection header is missing": {
			headers: http.Header{
				"Upgrade": []string{"websocket"},
			},
			expected: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)
			req.Header = tc.headers

			// WHEN
			actual := isUpgradeRequest(req)

			// THEN
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestIsNativeGRPCContentType(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		contentType string
		expected    bool
	}{
		"content type is missing": {
			expected: false,
		},
		"native gRPC content type": {
			contentType: "application/grpc",
			expected:    true,
		},
		"native gRPC content type is case insensitive": {
			contentType: "Application/GRPC",
			expected:    true,
		},
		"native gRPC proto subtype": {
			contentType: "application/grpc+proto",
			expected:    true,
		},
		"native gRPC json subtype": {
			contentType: "application/grpc+json",
			expected:    true,
		},
		"native gRPC content type with parameters": {
			contentType: "application/grpc+proto; charset=utf-8",
			expected:    true,
		},
		"native gRPC subtype must not be empty": {
			contentType: "application/grpc+",
			expected:    false,
		},
		"gRPC-Web content type": {
			contentType: "application/grpc-web",
			expected:    false,
		},
		"gRPC-Web proto subtype": {
			contentType: "application/grpc-web+proto",
			expected:    false,
		},
		"gRPC-Web text content type": {
			contentType: "application/grpc-web-text",
			expected:    false,
		},
		"non gRPC content type with gRPC prefix": {
			contentType: "application/grpcfoo",
			expected:    false,
		},
		"malformed content type": {
			contentType: "application grpc",
			expected:    false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			actual := isNativeGRPCContentType(tc.contentType)

			// THEN
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func assertTransportConfiguration(
	t *testing.T,
	transport *http.Transport,
	cfg config.ServeConfig,
	tlsCfg *tls.Config,
) {
	t.Helper()

	assert.NotNil(t, transport.Proxy)
	assert.NotNil(t, transport.DialContext)
	assert.Equal(t, cfg.Upstream.Responses.Headers.ReadTimeout, transport.ResponseHeaderTimeout)
	assert.Equal(t, int64(cfg.Upstream.Responses.Headers.MaxSize), transport.MaxResponseHeaderBytes)
	assert.Equal(t, cfg.Upstream.Connections.MaxIdle, transport.MaxIdleConns)
	assert.Equal(t, cfg.Upstream.Connections.MaxIdlePerHost, transport.MaxIdleConnsPerHost)
	assert.Equal(t, cfg.Upstream.Connections.MaxPerHost, transport.MaxConnsPerHost)
	assert.Equal(t, cfg.Upstream.Connections.IdleTimeout, transport.IdleConnTimeout)
	assert.Equal(t, cfg.Upstream.Connections.TLSHandshakeTimeout, transport.TLSHandshakeTimeout)
	assert.Equal(t, cfg.Upstream.Requests.ExpectContinueTimeout, transport.ExpectContinueTimeout)

	require.NotNil(t, transport.TLSClientConfig)
	assert.Equal(t, tlsCfg.MinVersion, transport.TLSClientConfig.MinVersion)
}

func assertTransportProtocols(
	t *testing.T,
	transport *http.Transport,
	http1 bool,
	http2 bool,
	unencryptedHTTP2 bool,
) {
	t.Helper()

	require.NotNil(t, transport.Protocols)

	assert.Equal(t, http1, transport.Protocols.HTTP1())
	assert.Equal(t, http2, transport.Protocols.HTTP2())
	assert.Equal(t, unencryptedHTTP2, transport.Protocols.UnencryptedHTTP2())
}
