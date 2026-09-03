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

package grpcv3

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"

	"github.com/dadrus/heimdall/internal/pipeline"
)

func TestNewRequestContext(t *testing.T) {
	t.Parallel()

	// GIVEN
	httpReq := &envoy_auth.AttributeContext_HttpRequest{
		Method: http.MethodPatch,
		Scheme: "https",
		Host:   "FoO.Bar:8080",
		Path:   "/test/baz?bar=moo#foobar",
		Headers: map[string]string{
			"x-foo-bar":       "barfoo",
			"x-forwarded-for": "127.0.0.1",
		},
	}
	checkReq := &envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Request: &envoy_auth.AttributeContext_Request{
				Http: httpReq,
			},
		},
	}

	grpcCtx := peer.NewContext(t.Context(), &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("192.168.1.1"),
			Port: 12345,
		},
	})

	cf := newContextFactory()
	ctx := cf.Create(grpcCtx, checkReq)

	defer cf.Destroy(ctx)

	// THEN
	assert.Equal(t, httpReq.GetMethod(), ctx.Request().Method)
	assert.Equal(t, httpReq.GetScheme(), ctx.Request().URL.Scheme)
	assert.Equal(t, "foo.bar:8080", ctx.Request().URL.Host)
	assert.Equal(t, "/test/baz", ctx.Request().URL.Path)
	assert.Empty(t, ctx.Request().URL.Fragment)
	assert.Equal(t, "bar=moo#foobar", ctx.Request().URL.RawQuery)
	assert.Equal(t, "moo#foobar", ctx.Request().URL.URL.Query().Get("bar"))
	assert.Equal(t, "foo.bar:8080", ctx.Request().Header("Host"))
	assert.Equal(t, "barfoo", ctx.Request().Header("X-Foo-Bar"))
	assert.Equal(t, grpcCtx, ctx.Context())
	assert.Equal(t, []string{"127.0.0.1", "192.168.1.1"}, ctx.Request().ClientIPAddresses)
}

func TestRequestContextURL(t *testing.T) {
	t.Parallel()

	cf := newContextFactory()

	for uc, tc := range map[string]struct {
		requestPath string
		path        string
		rawPath     string
		rawQuery    string
		forceQuery  bool
	}{
		"regular path": {
			requestPath: "/test/baz?bar=moo#foobar",
			path:        "/test/baz",
			rawPath:     "/test/baz",
			rawQuery:    "bar=moo#foobar",
		},
		"empty query": {
			requestPath: "/test?",
			path:        "/test",
			rawPath:     "/test",
			forceQuery:  true,
		},
		"escaped characters": {
			requestPath: "/test%2Ffoo/bar/%5Bval%5D?foo=bar",
			path:        "/test/foo/bar/[val]",
			rawPath:     "/test%2Ffoo/bar/%5Bval%5D",
			rawQuery:    "foo=bar",
		},
		"dot segments": {
			requestPath: "/bar/../test/foo/%5Bval%5D?bar=foo",
			path:        "/test/foo/[val]",
			rawPath:     "/test/foo/%5Bval%5D",
			rawQuery:    "bar=foo",
		},
		"encoded dot segments": {
			requestPath: "/bar/%2e.%2ftest/foo/%5Bval%5D?bar=foo",
			path:        "/bar/../test/foo/[val]",
			rawPath:     "/bar/%2e.%2ftest/foo/%5Bval%5D",
			rawQuery:    "bar=foo",
		},
		"encoded dot segments are retained if another byte requires escaping": {
			requestPath: "/admin/%2e%2e%2fpublic/x|",
			path:        "/admin/../public/x|",
			rawPath:     "/admin/%2e%2e%2fpublic/x%7C",
		},
		"encoded slash is retained if another byte requires escaping": {
			requestPath: "/files/a%2Fb|",
			path:        "/files/a/b|",
			rawPath:     "/files/a%2Fb%7C",
		},
		"trailing slash": {
			requestPath: "/bar/baz/",
			path:        "/bar/baz/",
			rawPath:     "/bar/baz/",
		},
		"root path": {
			requestPath: "/",
			path:        "/",
			rawPath:     "/",
		},
		"adjacent slashes": {
			requestPath: "/api//admin",
			path:        "/api/admin",
			rawPath:     "/api/admin",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			ctx := cf.Create(
				t.Context(),
				&envoy_auth.CheckRequest{
					Attributes: &envoy_auth.AttributeContext{
						Request: &envoy_auth.AttributeContext_Request{
							Http: &envoy_auth.AttributeContext_HttpRequest{
								Path: tc.requestPath,
							},
						},
					},
				},
			)

			defer cf.Destroy(ctx)

			assert.Equal(t, tc.path, ctx.Request().URL.Path)
			assert.Equal(t, tc.rawPath, ctx.Request().URL.RawPath)
			assert.Equal(t, tc.rawPath, ctx.Request().URL.EscapedPath())
			assert.Equal(t, tc.rawQuery, ctx.Request().URL.RawQuery)
			assert.Equal(t, tc.forceQuery, ctx.Request().URL.ForceQuery)
		})
	}
}

func TestRequestContextUpstreamRequest(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		prepared bool
	}{
		"upstream request is not available before preparation": {},
		"upstream request is available after preparation": {
			prepared: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			ctx := newRequestContext()
			ctx.Init(
				t.Context(),
				&envoy_auth.CheckRequest{
					Attributes: &envoy_auth.AttributeContext{
						Request: &envoy_auth.AttributeContext_Request{
							Http: &envoy_auth.AttributeContext_HttpRequest{
								Method: http.MethodGet,
								Scheme: "https",
								Host:   "foo.bar",
								Path:   "/test",
							},
						},
					},
				},
			)

			if tc.prepared {
				ctx.PrepareUpstreamView(nil)
			}

			// WHEN
			upstreamRequest := ctx.UpstreamRequest()

			// THEN
			if tc.prepared {
				require.NotNil(t, upstreamRequest)
				assert.Same(t, ctx, upstreamRequest)
			} else {
				assert.Nil(t, upstreamRequest)
			}
		})
	}
}

func TestRequestContextHeaders(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := newRequestContext()
	ctx.Init(
		t.Context(),
		&envoy_auth.CheckRequest{
			Attributes: &envoy_auth.AttributeContext{
				Request: &envoy_auth.AttributeContext_Request{
					Http: &envoy_auth.AttributeContext_HttpRequest{
						Host: "foo.bar",
						Headers: map[string]string{
							"x-foo":                     "bar",
							"x-envoy-auth-partial-body": "false",
						},
					},
				},
			},
		},
	)

	// WHEN
	headers := ctx.Headers()

	// THEN
	assert.Equal(t, "bar", headers.Get("X-Foo"))
	assert.Equal(t, "foo.bar", headers.Get("Host"))
	assert.Empty(t, headers.Get("X-Envoy-Auth-Partial-Body"))
}

func TestRequestContextFinalize(t *testing.T) {
	t.Parallel()

	cf := newContextFactory()

	findHeader := func(headers []*corev3.HeaderValueOption, name string) *corev3.HeaderValue {
		for _, header := range headers {
			if header.GetHeader().GetKey() == name {
				return header.GetHeader()
			}
		}

		return nil
	}

	for uc, tc := range map[string]struct {
		updateContext func(t *testing.T, ctx pipeline.ExecutionContext)
		assert        func(t *testing.T, err error, response *envoy_auth.CheckResponse)
	}{
		"successful with header mutations": {
			updateContext: func(t *testing.T, ctx pipeline.ExecutionContext) {
				t.Helper()

				ctx.PrepareUpstreamView(nil)

				upstreamRequest := ctx.UpstreamRequest()
				upstreamRequest.AddHeader("x-for-upstream-1", "some-value-1")
				upstreamRequest.AddHeader("x-for-upstream-2", "some-value-2")
				upstreamRequest.AddHeader("x-for-upstream-1", "some-value-3")
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, int32(codes.OK), response.GetStatus().GetCode())

				okResponse := response.GetOkResponse()
				require.NotNil(t, okResponse)
				require.Len(t, okResponse.GetHeaders(), 2)

				header := findHeader(okResponse.GetHeaders(), "X-For-Upstream-1")
				require.NotNil(t, header)
				assert.Equal(t, "some-value-1,some-value-3", header.GetValue())

				header = findHeader(okResponse.GetHeaders(), "X-For-Upstream-2")
				require.NotNil(t, header)
				assert.Equal(t, "some-value-2", header.GetValue())
			},
		},
		"explicit mutation is returned even if value equals incoming header": {
			updateContext: func(t *testing.T, ctx pipeline.ExecutionContext) {
				t.Helper()

				ctx.PrepareUpstreamView(nil)
				ctx.UpstreamRequest().SetHeader("X-Foo-Bar", "barfoo")
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, response)

				okResponse := response.GetOkResponse()
				require.NotNil(t, okResponse)
				require.Len(t, okResponse.GetHeaders(), 1)

				header := findHeader(okResponse.GetHeaders(), "X-Foo-Bar")
				require.NotNil(t, header)
				assert.Equal(t, "barfoo", header.GetValue())
			},
		},
		"internal partial body header is not returned": {
			updateContext: func(t *testing.T, ctx pipeline.ExecutionContext) {
				t.Helper()

				ctx.PrepareUpstreamView(nil)
				ctx.UpstreamRequest().SetHeader("X-Envoy-Auth-Partial-Body", "true")
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, response)

				okResponse := response.GetOkResponse()
				require.NotNil(t, okResponse)
				assert.Empty(t, okResponse.GetHeaders())
			},
		},
		"error is returned": {
			updateContext: func(t *testing.T, ctx pipeline.ExecutionContext) {
				t.Helper()

				ctx.SetError(assert.AnError)
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, response)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			httpReq := &envoy_auth.AttributeContext_HttpRequest{
				Method: http.MethodPatch,
				Scheme: "https",
				Host:   "foo.bar:8080",
				Path:   "/test",
				Headers: map[string]string{
					"x-foo-bar":                 "barfoo",
					"x-envoy-auth-partial-body": "false",
				},
			}
			checkReq := &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: httpReq,
					},
				},
			}

			ctx := cf.Create(t.Context(), checkReq)

			defer cf.Destroy(ctx)

			tc.updateContext(t, ctx)

			// WHEN
			resp, err := ctx.Finalize()

			// THEN
			tc.assert(t, err, resp)
		})
	}
}

func TestRequestContextRawBody(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		body              string
		rawBody           []byte
		partialBodyHeader string
		expected          string
	}{
		"no body": {
			partialBodyHeader: "false",
		},
		"raw body is available": {
			rawBody:           []byte("raw"),
			body:              "body",
			partialBodyHeader: "false",
			expected:          "raw",
		},
		"body is used if raw body is not available": {
			body:              "content=heimdall",
			partialBodyHeader: "false",
			expected:          "content=heimdall",
		},
		"partial body is treated as empty": {
			rawBody:           []byte("partial"),
			partialBodyHeader: "true",
		},
		"missing partial body indicator is treated as empty": {
			rawBody: []byte("content=heimdall"),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			headers := map[string]string{}
			if len(tc.partialBodyHeader) != 0 {
				headers["x-envoy-auth-partial-body"] = tc.partialBodyHeader
			}

			ctx := newRequestContext()
			ctx.Init(
				t.Context(),
				&envoy_auth.CheckRequest{
					Attributes: &envoy_auth.AttributeContext{
						Request: &envoy_auth.AttributeContext_Request{
							Http: &envoy_auth.AttributeContext_HttpRequest{
								Path:    "/test",
								Body:    tc.body,
								RawBody: tc.rawBody,
								Headers: headers,
							},
						},
					},
				},
			)

			// WHEN
			body, err := ctx.RawBody()

			// THEN
			require.NoError(t, err)
			require.NotNil(t, body)

			data, err := io.ReadAll(body)
			require.NoError(t, err)
			require.NoError(t, body.Close())

			assert.Equal(t, tc.expected, string(data))
		})
	}
}

func TestRequestContextReset(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := newRequestContext()
	ctx.Init(
		t.Context(),
		&envoy_auth.CheckRequest{
			Attributes: &envoy_auth.AttributeContext{
				Request: &envoy_auth.AttributeContext_Request{
					Http: &envoy_auth.AttributeContext_HttpRequest{
						Path:    "/test",
						RawBody: []byte("content=heimdall"),
						Headers: map[string]string{
							"x-envoy-auth-partial-body": "false",
						},
					},
				},
			},
		},
	)
	ctx.PrepareUpstreamView(nil)

	require.NotNil(t, ctx.bodySource.body)
	require.NotNil(t, ctx.UpstreamRequest())

	// WHEN
	ctx.Reset()

	// THEN
	require.Nil(t, ctx.bodySource.body)
	require.False(t, ctx.upstreamViewPrepared)
	require.Nil(t, ctx.UpstreamRequest())
	require.Nil(t, ctx.Context())
}

func TestRequestContextWithParent(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := newRequestContext()
	ctx.Init(
		context.TODO(),
		&envoy_auth.CheckRequest{
			Attributes: &envoy_auth.AttributeContext{
				Request: &envoy_auth.AttributeContext_Request{
					Http: &envoy_auth.AttributeContext_HttpRequest{},
				},
			},
		},
	)

	orig := ctx.Context()

	// WHEN
	actual := ctx.WithParent(t.Context())

	// THEN
	assert.Same(t, ctx, actual)
	assert.NotEqual(t, orig, ctx.Context())
	assert.Equal(t, t.Context(), ctx.Context())
}

func TestCanonicalizeHeaders(t *testing.T) {
	t.Parallel()

	// GIVEN
	headers := map[string]string{
		"x-foo":   "bar",
		"X-bAZ":   "foo",
		"cOntEnT": "value",
	}

	// WHEN
	actual := canonicalizeHeaders(headers)

	// THEN
	assert.Equal(t, http.Header{
		"X-Foo":   []string{"bar"},
		"X-Baz":   []string{"foo"},
		"Content": []string{"value"},
	}, actual)
}

func TestPeerAddress(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ctx      func(t *testing.T) context.Context
		expected string
	}{
		"peer address is available": {
			ctx: func(t *testing.T) context.Context {
				t.Helper()

				return peer.NewContext(t.Context(), &peer.Peer{
					Addr: &net.TCPAddr{
						IP:   net.ParseIP("192.0.2.1"),
						Port: 12345,
					},
				})
			},
			expected: "192.0.2.1:12345",
		},
		"peer is not available": {
			ctx: func(t *testing.T) context.Context {
				t.Helper()

				return t.Context()
			},
		},
		"peer address is not available": {
			ctx: func(t *testing.T) context.Context {
				t.Helper()

				return peer.NewContext(t.Context(), &peer.Peer{})
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			actual := peerAddress(tc.ctx(t))

			// THEN
			assert.Equal(t, tc.expected, actual)
		})
	}
}
