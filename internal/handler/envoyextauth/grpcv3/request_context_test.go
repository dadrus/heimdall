package grpcv3

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestNewRequestContext(t *testing.T) {
	t.Parallel()

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
			"x-foo-bar":    "barfoo",
			"cookie":       "bar=foo;foo=baz",
			"content-type": "application/x-www-form-urlencoded",
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
	md.Set("x-forwarded-for", "127.0.0.1", "192.168.1.1")

	ctx := NewRequestContext(
		metadata.NewIncomingContext(
			context.Background(),
			md,
		),
		checkReq,
		&mocks.MockJWTSigner{},
	)

	// THEN
	require.Equal(t, httpReq.Method, ctx.RequestMethod())
	require.Equal(t, httpReq.Scheme, ctx.RequestURL().Scheme)
	require.Equal(t, httpReq.Host, ctx.RequestURL().Host)
	require.Equal(t, httpReq.Path, ctx.RequestURL().Path)
	require.Equal(t, httpReq.Fragment, ctx.RequestURL().Fragment)
	require.Equal(t, httpReq.Query, ctx.RequestURL().RawQuery)
	require.Equal(t, "moo", ctx.RequestQueryParameter("bar"))
	require.Equal(t, httpReq.RawBody, ctx.RequestBody())
	require.Empty(t, ctx.RequestFormParameter("foo"))
	require.Equal(t, "heimdall", ctx.RequestFormParameter("content"))
	require.Len(t, ctx.RequestHeaders(), 3)
	require.Equal(t, "barfoo", ctx.RequestHeader("X-Foo-Bar"))
	require.Equal(t, "foo", ctx.RequestCookie("bar"))
	require.Equal(t, "baz", ctx.RequestCookie("foo"))
	require.Empty(t, ctx.RequestCookie("baz"))
	require.NotNil(t, ctx.AppContext())
	require.NotNil(t, ctx.Signer())
	assert.Equal(t, ctx.RequestClientIPs(), []string{"127.0.0.1", "192.168.1.1"})
}

func TestFinalizeRequestContext(t *testing.T) {
	t.Parallel()

	findHeader := func(headers []*corev3.HeaderValueOption, name string) *corev3.HeaderValue {
		for _, header := range headers {
			if header.Header.Key == name {
				return header.Header
			}
		}

		return nil
	}

	for _, tc := range []struct {
		uc            string
		updateContext func(t *testing.T, ctx heimdall.Context)
		assert        func(t *testing.T, err error, response *envoy_auth.CheckResponse)
	}{
		{
			uc: "successful with some header",
			updateContext: func(t *testing.T, ctx heimdall.Context) {
				t.Helper()

				ctx.AddHeaderForUpstream("x-for-upstream-1", "some-value-1")
				ctx.AddHeaderForUpstream("x-for-upstream-2", "some-value-2")
				ctx.AddHeaderForUpstream("x-for-upstream-1", "some-value-3")
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, response)

				assert.Equal(t, int32(http.StatusOK), response.Status.Code)

				okResponse := response.GetOkResponse()
				require.NotNil(t, okResponse)

				require.Len(t, okResponse.Headers, 2)

				header := findHeader(okResponse.Headers, "X-For-Upstream-1")
				require.NotNil(t, header)
				assert.Equal(t, "some-value-1,some-value-3", header.Value)
				header = findHeader(okResponse.Headers, "X-For-Upstream-2")
				require.NotNil(t, header)
				assert.Equal(t, "some-value-2", header.Value)
			},
		},
		{
			uc: "successful with some cookies",
			updateContext: func(t *testing.T, ctx heimdall.Context) {
				t.Helper()

				ctx.AddCookieForUpstream("some-cookie", "value-1")
				ctx.AddCookieForUpstream("some-other-cookie", "value-2")
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, response)

				assert.Equal(t, int32(http.StatusOK), response.Status.Code)

				okResponse := response.GetOkResponse()
				require.NotNil(t, okResponse)

				require.Len(t, okResponse.Headers, 1)
				assert.Equal(t, "Cookie", okResponse.Headers[0].Header.Key)
				values := strings.Split(okResponse.Headers[0].Header.Value, ";")
				assert.Len(t, values, 2)
				assert.Contains(t, okResponse.Headers[0].Header.Value, "some-cookie=value-1")
				assert.Contains(t, okResponse.Headers[0].Header.Value, "some-other-cookie=value-2")
			},
		},
		{
			uc: "successful with header and cookie",
			updateContext: func(t *testing.T, ctx heimdall.Context) {
				t.Helper()

				ctx.AddHeaderForUpstream("x-for-upstream", "some-value")
				ctx.AddCookieForUpstream("some-cookie", "value-1")
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, response)

				assert.Equal(t, int32(http.StatusOK), response.Status.Code)

				okResponse := response.GetOkResponse()
				require.NotNil(t, okResponse)

				require.Len(t, okResponse.Headers, 2)
				header := findHeader(okResponse.Headers, "X-For-Upstream")
				require.NotNil(t, header)
				assert.Equal(t, "some-value", header.Value)
				header = findHeader(okResponse.Headers, "Cookie")
				require.NotNil(t, header)
				assert.Equal(t, "some-cookie=value-1", header.Value)
			},
		},
		{
			uc: "erroneous with header and cookie",
			updateContext: func(t *testing.T, ctx heimdall.Context) {
				t.Helper()

				ctx.SetPipelineError(errors.New("test error")) // nolint: goerr113
				ctx.AddHeaderForUpstream("x-for-upstream", "some-value")
				ctx.AddCookieForUpstream("some-cookie", "value-1")
				ctx.AddCookieForUpstream("some-other-cookie", "value-2")
			},
			assert: func(t *testing.T, err error, response *envoy_auth.CheckResponse) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, err.Error(), "test error")
				require.Nil(t, response)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
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
					"x-foo-bar":    "barfoo",
					"cookie":       "bar=foo;foo=baz",
					"content-type": "application/x-www-form-urlencoded",
				},
			}
			checkReq := &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: httpReq,
					},
				},
			}
			ctx := NewRequestContext(context.Background(), checkReq, nil)

			tc.updateContext(t, ctx)

			// WHEN
			resp, err := ctx.Finalize()

			// THEN
			tc.assert(t, err, resp)
		})
	}
}
