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
	"errors"
	"io"
	"net"
	"net/http"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/dadrus/heimdall/internal/pipeline"
)

func TestNewRequestContext(t *testing.T) {
	t.Parallel()

	// GIVEN
	httpReq := &envoy_auth.AttributeContext_HttpRequest{
		Method:   http.MethodPatch,
		Scheme:   "https",
		Host:     "FoO.Bar:8080",
		Path:     "/test/baz?bar=moo#foobar",
		Query:    "", // documented to be empty
		Fragment: "", // documented to be empty
		Body:     "content=heimdall",
		RawBody:  []byte("content=heimdall"),
		Headers: map[string]string{
			"x-foo-bar":                 "barfoo",
			"cookie":                    "bar=foo;foo=baz",
			"content-type":              "application/x-www-form-urlencoded",
			"x-forwarded-for":           "127.0.0.1",
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

	md := metadata.New(nil)
	md.Set("x-forwarded-for", "203.0.113.1")

	grpcCtx := metadata.NewIncomingContext(t.Context(), md)
	grpcCtx = peer.NewContext(grpcCtx, &peer.Peer{
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
	assert.Equal(t, map[string]any{"content": []string{"heimdall"}}, ctx.Request().Body())
	require.Len(t, ctx.Request().Headers(), 6)
	assert.Equal(t, "foo.bar:8080", ctx.Request().Header("Host"))
	assert.Equal(t, "barfoo", ctx.Request().Header("X-Foo-Bar"))
	assert.Equal(t, "127.0.0.1", ctx.Request().Header("X-Forwarded-For"))
	assert.Equal(t, "foo", ctx.Request().Cookie("bar"))
	assert.Equal(t, "baz", ctx.Request().Cookie("foo"))
	assert.Empty(t, ctx.Request().Cookie("baz"))
	assert.NotNil(t, ctx.Context())
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

func TestRequestContextUpstreamURL(t *testing.T) {
	t.Parallel()

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
						Host:   "FoO.Bar:8080",
						Path:   "/test?foo=bar",
					},
				},
			},
		},
	)
	ctx.PrepareUpstreamView(nil)

	upstreamRequest := ctx.UpstreamRequest()

	// WHEN
	upstreamURL := upstreamRequest.URL()

	// THEN
	assert.Equal(t, "https", upstreamURL.Scheme)
	assert.Equal(t, "foo.bar:8080", upstreamURL.Host)
	assert.Equal(t, "/test", upstreamURL.Path)
	assert.Equal(t, "foo=bar", upstreamURL.RawQuery)

	upstreamURL.Host = "changed.local"
	upstreamURL.Path = "/changed"

	assert.Equal(t, "foo.bar:8080", upstreamRequest.URL().Host)
	assert.Equal(t, "/test", upstreamRequest.URL().Path)

	upstreamRequest.SetHeader("Host", "bar.foo")

	assert.Equal(t, "bar.foo", upstreamRequest.URL().Host)
	assert.Equal(t, "/test", upstreamRequest.URL().Path)
}

func TestRequestContextAddHeader(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		name                 string
		values               []string
		expectedHeaderValues []string
		expectedURLHost      string
	}{
		"header is added": {
			name:                 "X-Foo",
			values:               []string{"bar"},
			expectedHeaderValues: []string{"bar"},
			expectedURLHost:      "foo.bar",
		},
		"multiple header values are added": {
			name:                 "X-Foo",
			values:               []string{"bar", "foo"},
			expectedHeaderValues: []string{"bar", "foo"},
			expectedURLHost:      "foo.bar",
		},
		"Host is treated as regular upstream header": {
			name:                 "Host",
			values:               []string{"bar.foo"},
			expectedHeaderValues: []string{"bar.foo"},
			expectedURLHost:      "bar.foo",
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
			ctx.PrepareUpstreamView(nil)
			upstreamRequest := ctx.UpstreamRequest()

			// WHEN
			for _, value := range tc.values {
				upstreamRequest.AddHeader(tc.name, value)
			}

			// THEN
			assert.ElementsMatch(
				t,
				tc.expectedHeaderValues,
				upstreamRequest.Headers().Values(tc.name),
			)
			assert.Equal(t, tc.expectedURLHost, upstreamRequest.URL().Host)
		})
	}
}

func TestRequestContextSetHeader(t *testing.T) {
	t.Parallel()

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
						Headers: map[string]string{
							"x-foo": "incoming",
						},
					},
				},
			},
		},
	)
	ctx.PrepareUpstreamView(nil)

	upstreamRequest := ctx.UpstreamRequest()
	upstreamRequest.AddHeader("X-Foo", "first")
	upstreamRequest.AddHeader("X-Foo", "second")

	// WHEN
	upstreamRequest.SetHeader("X-Foo", "replaced")
	upstreamRequest.SetHeader("Host", "bar.foo")

	// THEN
	assert.Equal(t, []string{"replaced"}, upstreamRequest.Headers().Values("X-Foo"))
	assert.Equal(t, []string{"bar.foo"}, upstreamRequest.Headers().Values("Host"))
	assert.Equal(t, "bar.foo", upstreamRequest.URL().Host)
}

func TestRequestContextSetCookie(t *testing.T) {
	t.Parallel()

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
						Headers: map[string]string{
							"cookie": "foo=old; session=abc",
						},
					},
				},
			},
		},
	)
	ctx.PrepareUpstreamView(nil)

	upstreamRequest := ctx.UpstreamRequest()

	// WHEN
	upstreamRequest.SetCookie("foo", "new")

	// THEN
	assert.Equal(t, "session=abc; foo=new", upstreamRequest.Headers().Get("Cookie"))

	upstreamRequest.SetCookie("session", "changed")

	assert.Equal(t, "foo=new; session=changed", upstreamRequest.Headers().Get("Cookie"))
}

func TestRequestContextUpstreamHeaders(t *testing.T) {
	t.Parallel()

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
						Headers: map[string]string{
							"x-foo":                     "incoming",
							"cookie":                    "foo=bar",
							"x-envoy-auth-partial-body": "false",
						},
					},
				},
			},
		},
	)
	ctx.PrepareUpstreamView(nil)

	upstreamRequest := ctx.UpstreamRequest()
	upstreamRequest.AddHeader("X-Foo", "from-heimdall")
	upstreamRequest.SetHeader("X-Set", "set-by-heimdall")
	upstreamRequest.SetCookie("bar", "foo")

	// WHEN
	headers := upstreamRequest.Headers()

	// THEN
	assert.Equal(t, []string{"from-heimdall"}, headers.Values("X-Foo"))
	assert.Equal(t, "set-by-heimdall", headers.Get("X-Set"))
	assert.Equal(t, "foo=bar; bar=foo", headers.Get("Cookie"))
	assert.Equal(t, "foo.bar", headers.Get("Host"))
	assert.Empty(t, headers.Get("X-Envoy-Auth-Partial-Body"))

	headers.Set("X-Foo", "changed")
	headers.Set("Host", "changed.local")

	current := upstreamRequest.Headers()

	assert.Equal(t, []string{"from-heimdall"}, current.Values("X-Foo"))
	assert.Equal(t, "foo.bar", current.Get("Host"))
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
		"successful with some different header": {
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
		"successful with multiple header with same name but different values": {
			updateContext: func(t *testing.T, ctx pipeline.ExecutionContext) {
				t.Helper()

				ctx.PrepareUpstreamView(nil)

				upstreamRequest := ctx.UpstreamRequest()
				upstreamRequest.AddHeader("x-for-upstream-1", "some-value-1")
				upstreamRequest.AddHeader("x-for-upstream-1", "some-value-2")
				upstreamRequest.AddHeader("x-for-upstream-1", "some-value-3")
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, response)

				assert.Equal(t, int32(codes.OK), response.GetStatus().GetCode())

				okResponse := response.GetOkResponse()
				require.NotNil(t, okResponse)

				require.Len(t, okResponse.GetHeaders(), 1)

				header := findHeader(okResponse.GetHeaders(), "X-For-Upstream-1")
				require.NotNil(t, header)
				assert.Equal(t, "some-value-1,some-value-2,some-value-3", header.GetValue())
			},
		},
		"successful with some cookies": {
			updateContext: func(t *testing.T, ctx pipeline.ExecutionContext) {
				t.Helper()

				ctx.PrepareUpstreamView(nil)

				upstreamRequest := ctx.UpstreamRequest()
				upstreamRequest.SetCookie("some-cookie", "value-1")
				upstreamRequest.SetCookie("some-other-cookie", "value-2")
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, response)

				assert.Equal(t, int32(codes.OK), response.GetStatus().GetCode())

				okResponse := response.GetOkResponse()
				require.NotNil(t, okResponse)

				require.Len(t, okResponse.GetHeaders(), 1)

				header := findHeader(okResponse.GetHeaders(), "Cookie")
				require.NotNil(t, header)

				cookies, err := http.ParseCookie(header.GetValue())
				require.NoError(t, err)
				require.Len(t, cookies, 4)

				cookieValues := make(map[string]string, len(cookies))
				for _, cookie := range cookies {
					cookieValues[cookie.Name] = cookie.Value
				}

				assert.Equal(t, map[string]string{
					"bar":               "foo",
					"foo":               "baz",
					"some-cookie":       "value-1",
					"some-other-cookie": "value-2",
				}, cookieValues)
			},
		},
		"successful with multiple header and cookie": {
			updateContext: func(t *testing.T, ctx pipeline.ExecutionContext) {
				t.Helper()

				ctx.PrepareUpstreamView(nil)

				upstreamRequest := ctx.UpstreamRequest()
				upstreamRequest.AddHeader("x-for-upstream", "some-value")
				upstreamRequest.SetCookie("some-cookie", "value-1")
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, response)

				assert.Equal(t, int32(codes.OK), response.GetStatus().GetCode())

				okResponse := response.GetOkResponse()
				require.NotNil(t, okResponse)

				require.Len(t, okResponse.GetHeaders(), 2)

				header := findHeader(okResponse.GetHeaders(), "X-For-Upstream")
				require.NotNil(t, header)
				assert.Equal(t, "some-value", header.GetValue())

				header = findHeader(okResponse.GetHeaders(), "Cookie")
				require.NotNil(t, header)
				assert.Equal(t, "bar=foo; foo=baz; some-cookie=value-1", header.GetValue())
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
		"erroneous with header and cookie": {
			updateContext: func(t *testing.T, ctx pipeline.ExecutionContext) {
				t.Helper()

				ctx.PrepareUpstreamView(nil)

				ctx.SetError(assert.AnError)
				ctx.UpstreamRequest().AddHeader("x-for-upstream", "some-value")
				ctx.UpstreamRequest().SetCookie("some-cookie", "value-1")
				ctx.UpstreamRequest().SetCookie("some-other-cookie", "value-2")
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Nil(t, response)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			httpReq := &envoy_auth.AttributeContext_HttpRequest{
				Method:   http.MethodPatch,
				Scheme:   "https",
				Host:     "foo.bar:8080",
				Path:     "/test",
				Query:    "bar=moo",
				Fragment: "foobar",
				Body:     "content=heimdall",
				RawBody:  []byte("content=heimdall"),
				Headers: map[string]string{
					"x-foo-bar":                 "barfoo",
					"cookie":                    "bar=foo;foo=baz",
					"content-type":              "application/x-www-form-urlencoded",
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
			rawBody:           []byte("content=heimdall"),
			partialBodyHeader: "false",
			expected:          "content=heimdall",
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
			ctx.PrepareUpstreamView(nil)

			// WHEN
			body, err := ctx.UpstreamRequest().RawBody()

			// THEN
			require.NoError(t, err)
			require.NotNil(t, body)

			data, err := io.ReadAll(body)
			require.NoError(t, err)
			require.NoError(t, body.Close())

			assert.Equal(t, tc.expected, string(data))

			body, err = ctx.UpstreamRequest().RawBody()
			require.NoError(t, err)
			require.NotNil(t, body)

			data, err = io.ReadAll(body)
			require.NoError(t, err)
			require.NoError(t, body.Close())

			assert.Equal(t, tc.expected, string(data))
		})
	}
}

func TestRequestContextBody(t *testing.T) {
	t.Parallel()

	cf := newContextFactory()

	for uc, tc := range map[string]struct {
		ct     string
		body   []byte
		expect any
	}{
		"No body": {
			ct:     "empty",
			body:   nil,
			expect: "",
		},
		"Empty body": {
			ct:     "empty",
			body:   []byte(""),
			expect: "",
		},
		"Wrong content type": {
			ct:     "application/json",
			body:   []byte("foo: bar"),
			expect: "foo: bar",
		},
		"x-www-form-urlencoded encoded": {
			ct:     "application/x-www-form-urlencoded; charset=utf-8",
			body:   []byte("content=heimdall"),
			expect: map[string]any{"content": []string{"heimdall"}},
		},
		"json encoded": {
			ct:     "application/json; charset=utf-8",
			body:   []byte(`{ "content": "heimdall" }`),
			expect: map[string]any{"content": "heimdall"},
		},
		"json encoded array": {
			ct:     "application/json; charset=utf-8",
			body:   []byte(`[{"content": "heimdall"}]`),
			expect: []any{map[string]any{"content": "heimdall"}},
		},
		"json encoded scalar string": {
			ct:     "application/json; charset=utf-8",
			body:   []byte(`"heimdall"`),
			expect: "heimdall",
		},
		"json encoded scalar number": {
			ct:     "application/json; charset=utf-8",
			body:   []byte(`42`),
			expect: float64(42),
		},
		"json encoded scalar bool": {
			ct:     "application/json; charset=utf-8",
			body:   []byte(`true`),
			expect: true,
		},
		"json encoded null": {
			ct:     "application/json; charset=utf-8",
			body:   []byte(`null`),
			expect: nil,
		},
		"yaml encoded": {
			ct:     "application/yaml; charset=utf-8",
			body:   []byte("content: heimdall"),
			expect: map[string]any{"content": "heimdall"},
		},
		"yaml encoded sequence": {
			ct:     "application/yaml; charset=utf-8",
			body:   []byte("- content: heimdall\n"),
			expect: []any{map[string]any{"content": "heimdall"}},
		},
		"yaml encoded scalar": {
			ct:     "application/yaml; charset=utf-8",
			body:   []byte("heimdall\n"),
			expect: "heimdall",
		},
		"plain text": {
			ct:     "text/plain",
			body:   []byte("content=heimdall"),
			expect: "content=heimdall",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			ctx := cf.Create(
				t.Context(),
				&envoy_auth.CheckRequest{
					Attributes: &envoy_auth.AttributeContext{
						Request: &envoy_auth.AttributeContext_Request{
							Http: &envoy_auth.AttributeContext_HttpRequest{
								Path:    "/test",
								RawBody: tc.body,
								Headers: map[string]string{
									"content-type":              tc.ct,
									"x-envoy-auth-partial-body": "false",
								},
							},
						},
					},
				},
			)

			defer cf.Destroy(ctx)

			// WHEN
			data := ctx.Request().Body()

			// THEN
			assert.Equal(t, tc.expect, data)
		})
	}
}

func TestRequestContextRequestURLCaptures(t *testing.T) {
	t.Parallel()

	// GIVEN
	cf := newContextFactory()
	ctx := cf.Create(
		t.Context(),
		&envoy_auth.CheckRequest{
			Attributes: &envoy_auth.AttributeContext{
				Request: &envoy_auth.AttributeContext_Request{
					Http: &envoy_auth.AttributeContext_HttpRequest{
						Path:    "/test",
						RawBody: []byte("foo"),
						Headers: map[string]string{
							"content-type":              "application/json",
							"x-envoy-auth-partial-body": "false",
						},
					},
				},
			},
		},
	)

	defer cf.Destroy(ctx)

	ctx.Request().URL.Captures = map[string]string{"a": "b"}

	// WHEN
	captures := ctx.Request().URL.Captures

	// THEN
	require.Len(t, captures, 1)
	assert.Equal(t, "b", captures["a"])
}

func TestRequestContextReset(t *testing.T) {
	t.Parallel()

	checkReq := &envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Request: &envoy_auth.AttributeContext_Request{
				Http: &envoy_auth.AttributeContext_HttpRequest{
					Method:  http.MethodPatch,
					Scheme:  "https",
					Host:    "foo.bar:8080",
					Path:    "/test",
					Query:   "bar=moo",
					RawBody: []byte(`{ "content": "heimdall" }`),
					Headers: map[string]string{
						"content-type":              "application/json",
						"x-forwarded-for":           "127.0.0.1",
						"x-envoy-auth-partial-body": "false",
					},
				},
			},
		},
	}

	grpcCtx := peer.NewContext(context.TODO(), &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("192.168.1.1"),
			Port: 12345,
		},
	})

	// GIVEN
	ctx := newRequestContext()
	ctx.Init(grpcCtx, checkReq)
	ctx.Request().URL.Captures = map[string]string{"b": "a"}
	ctx.SetError(errors.New("test error"))
	_ = ctx.Body()
	ctx.Outputs()["b"] = pipeline.NewResult("c")
	ctx.PrepareUpstreamView(nil)
	ctx.UpstreamRequest().SetCookie("foo", "bar")
	ctx.UpstreamRequest().AddHeader("bar", "foo")
	_ = ctx.UpstreamRequest().Headers()

	require.Equal(
		t,
		[]string{"127.0.0.1", "192.168.1.1"},
		ctx.Request().ClientIPAddresses,
	)

	// WHEN
	ctx.Reset()

	// THEN
	require.Nil(t, ctx.ctx)
	require.Nil(t, ctx.reqHeaders)
	require.Nil(t, ctx.reqBody)
	require.Nil(t, ctx.savedBody)
	require.NoError(t, ctx.err)
	require.False(t, ctx.upstreamViewPrepared)
	require.Nil(t, ctx.UpstreamRequest())
	require.NotNil(t, ctx.results)
	require.Empty(t, ctx.results)
	require.NotNil(t, ctx.upstreamHeaders)
	require.Empty(t, ctx.upstreamHeaders)
	require.NotNil(t, ctx.hmdlReq)
	require.NotNil(t, ctx.hmdlReq.URL)
	require.Empty(t, ctx.hmdlReq.URL.URL)
	require.Empty(t, ctx.hmdlReq.Method)
	require.NotNil(t, ctx.hmdlReq.URL.Captures)
	require.Empty(t, ctx.hmdlReq.URL.Captures)
	require.NotNil(t, ctx.hmdlReq.ClientIPAddresses)
	require.Empty(t, ctx.hmdlReq.ClientIPAddresses)
	require.Equal(t, 10, cap(ctx.hmdlReq.ClientIPAddresses))
}

func TestRequestContextWithParent(t *testing.T) {
	t.Parallel()

	// GIVEN
	checkReq := &envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Request: &envoy_auth.AttributeContext_Request{
				Http: &envoy_auth.AttributeContext_HttpRequest{
					Method:  http.MethodPatch,
					Scheme:  "https",
					Host:    "foo.bar:8080",
					Path:    "/test",
					Query:   "bar=moo",
					RawBody: []byte(`{ "content": "heimdall" }`),
					Headers: map[string]string{
						"content-type":              "application/json",
						"x-envoy-auth-partial-body": "false",
					},
				},
			},
		},
	}

	md := metadata.MD{
		"x-forwarded-for": []string{"127.0.0.1"},
	}

	ctx := newRequestContext()
	ctx.Init(metadata.NewIncomingContext(context.TODO(), md), checkReq)

	orig := ctx.Context()

	ctx.WithParent(t.Context())

	assert.NotEqual(t, orig, ctx.ctx)
	assert.Equal(t, t.Context(), ctx.ctx)
}

func TestRequestContextHeader(t *testing.T) {
	t.Parallel()

	cf := newContextFactory()

	for uc, tc := range map[string]struct {
		name     string
		expected string
	}{
		"canonical header name": {
			name:     "X-Foo",
			expected: "bar",
		},
		"lowercase header name": {
			name:     "x-foo",
			expected: "bar",
		},
		"uppercase header name": {
			name:     "X-FOO",
			expected: "bar",
		},
		"mixed case header name": {
			name:     "x-FoO",
			expected: "bar",
		},
		"unknown header": {
			name:     "X-Bar",
			expected: "",
		},
		"lowercase host header": {
			name:     "host",
			expected: "foo.bar",
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
								Host: "FoO.Bar",
								Headers: map[string]string{
									"x-foo": "bar",
								},
							},
						},
					},
				},
			)
			defer cf.Destroy(ctx)

			assert.Equal(t, tc.expected, ctx.Request().Header(tc.name))
		})
	}
}

func TestRequestClientIPs(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		headers  map[string]string
		expected []string
	}{
		"neither Forwarded, nor X-Forwarded-For headers are present": {
			headers: map[string]string{},
			expected: []string{
				"192.0.2.1",
			},
		},
		"only Forwarded header is present": {
			headers: map[string]string{
				"Forwarded": "proto=http;for=127.0.0.1, proto=https;for=192.168.12.125",
			},
			expected: []string{
				"127.0.0.1",
				"192.168.12.125",
				"192.0.2.1",
			},
		},
		"only X-Forwarded-For header is present": {
			headers: map[string]string{
				"X-Forwarded-For": "127.0.0.1, 192.168.12.125",
			},
			expected: []string{
				"127.0.0.1",
				"192.168.12.125",
				"192.0.2.1",
			},
		},
		"Forwarded and X-Forwarded-For headers are present": {
			headers: map[string]string{
				"X-Forwarded-For": "127.0.0.2, 192.168.12.126",
				"Forwarded":       "proto=http;for=127.0.0.3, proto=http;for=192.168.12.127",
			},
			expected: []string{
				"127.0.0.3",
				"192.168.12.127",
				"192.0.2.1",
			},
		},
		"X-Forwarded-For contains multiple and empty values": {
			headers: map[string]string{
				"X-Forwarded-For": "127.0.0.1, 192.168.1.1, 10.0.0.2,   ",
			},
			expected: []string{
				"127.0.0.1",
				"192.168.1.1",
				"10.0.0.2",
				"192.0.2.1",
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			md := metadata.New(nil)
			md.Set("x-forwarded-for", "203.0.113.1")

			ctx := metadata.NewIncomingContext(t.Context(), md)
			ctx = peer.NewContext(ctx, &peer.Peer{
				Addr: &net.TCPAddr{
					IP:   net.ParseIP("192.0.2.1"),
					Port: 12345,
				},
			})

			// WHEN
			ips := requestClientIPs(
				ctx,
				make([]string, 0, 10),
				tc.headers,
			)

			// THEN
			assert.Equal(t, tc.expected, ips)
		})
	}
}
