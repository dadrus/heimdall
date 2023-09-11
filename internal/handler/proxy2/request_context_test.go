package proxy2

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/request"
	mocks2 "github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

func TestRequestContextRequestClientIPs(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc               string
		configureRequest func(t *testing.T, req *http.Request)
		assert           func(t *testing.T, ips []string)
	}{
		{
			"neither Forwarded, not X-Forwarded-For headers are present",
			func(t *testing.T, req *http.Request) { t.Helper() },
			func(t *testing.T, ips []string) {
				t.Helper()

				require.Len(t, ips, 1)
				assert.Contains(t, ips, "192.0.2.1")
			},
		},
		{
			"only Forwarded header is present",
			func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("Forwarded", "proto=http;for=127.0.0.1, proto=https;for=192.168.12.125")
			},
			func(t *testing.T, ips []string) {
				t.Helper()

				require.Len(t, ips, 3)

				assert.Equal(t, "127.0.0.1", ips[0])
				assert.Equal(t, "192.168.12.125", ips[1])
				assert.Equal(t, "192.0.2.1", ips[2])
			},
		},
		{
			"only X-Forwarded-For header is present",
			func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-For", "127.0.0.1, 192.168.12.125")
			},
			func(t *testing.T, ips []string) {
				t.Helper()

				require.Len(t, ips, 3)

				assert.Equal(t, "127.0.0.1", ips[0])
				assert.Equal(t, "192.168.12.125", ips[1])
				assert.Equal(t, "192.0.2.1", ips[2])
			},
		},
		{
			"Forwarded and X-Forwarded-For headers are present",
			func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-For", "127.0.0.2, 192.168.12.126")
				req.Header.Set("Forwarded", "proto=http;for=127.0.0.3, proto=http;for=192.168.12.127")
			},
			func(t *testing.T, ips []string) {
				t.Helper()

				require.Len(t, ips, 3)

				assert.Equal(t, "127.0.0.3", ips[0])
				assert.Equal(t, "192.168.12.127", ips[1])
				assert.Equal(t, "192.0.2.1", ips[2])
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequest(http.MethodHead, "https://foo.bar/test", nil)
			tc.configureRequest(t, req)

			ctx := &requestContext{req: req}

			// WHEN
			ips := ctx.requestClientIPs()

			// THEN
			tc.assert(t, ips)
		})
	}
}

func TestRequestContextFinalize(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		upstreamCalled bool
		headers        http.Header
		setup          func(*testing.T, request.Context, *mocks2.URIMutatorMock, *url.URL)
		assertRequest  func(*testing.T, *http.Request)
	}{
		{
			uc: "error was present, forwarding aborted",
			setup: func(t *testing.T, ctx request.Context, _ *mocks2.URIMutatorMock, _ *url.URL) {
				t.Helper()

				err := errors.New("test error")
				ctx.SetPipelineError(err)
			},
		},
		{
			uc: "error while retrieving target url",
			setup: func(t *testing.T, ctx request.Context, mut *mocks2.URIMutatorMock, _ *url.URL) {
				t.Helper()

				err := errors.New("test error")
				mut.EXPECT().Mutate(mock.Anything).Return(nil, err)
			},
		},
		{
			uc:             "no headers set",
			upstreamCalled: true,
			setup: func(t *testing.T, _ request.Context, mut *mocks2.URIMutatorMock, uri *url.URL) {
				t.Helper()

				mut.EXPECT().Mutate(mock.Anything).Return(uri, nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 3)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "for=192.0.2.1;host=foo.bar;proto=https", req.Header.Get("Forwarded"))
			},
		},
		{
			uc:             "all X-Forwarded-* and Forwarded headers present",
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-Proto":  []string{"https"},
				"X-Forwarded-Host":   []string{"bar.foo"},
				"X-Forwarded-Path":   []string{"/foobar"},
				"X-Forwarded-Uri":    []string{"/barfoo?foo=bar"},
				"X-Forwarded-Method": []string{http.MethodPatch},
				"X-Forwarded-For":    []string{"127.0.0.2, 192.168.12.126"},
				"Forwarded":          []string{"proto=http;for=127.0.0.3, proto=http;for=192.168.12.127"},
			},
			setup: func(t *testing.T, _ request.Context, mut *mocks2.URIMutatorMock, uri *url.URL) {
				t.Helper()

				mut.EXPECT().Mutate(mock.Anything).Return(uri, nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodPatch, req.Method)

				require.Len(t, req.Header, 5)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "127.0.0.2, 192.168.12.126, 192.0.2.1", req.Header.Get("X-Forwarded-For"))
				assert.Equal(t, "bar.foo", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
			},
		},
		{
			uc:             "only X-Forwarded-Method and Forwarded headers are present",
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-Method": []string{http.MethodPost},
				"Forwarded":          []string{"proto=http;for=127.0.0.3, proto=http;for=192.168.12.127"},
			},
			setup: func(t *testing.T, _ request.Context, mut *mocks2.URIMutatorMock, uri *url.URL) {
				t.Helper()

				mut.EXPECT().Mutate(mock.Anything).Return(uri, nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodPost, req.Method)

				require.Len(t, req.Header, 3)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "proto=http;for=127.0.0.3, proto=http;for=192.168.12.127, for=192.0.2.1;host=foo.bar;proto=https", req.Header.Get("Forwarded"))
			},
		},
		{
			uc:             "only custom headers and results from rule execution are present",
			upstreamCalled: true,
			headers: http.Header{
				"X-Foo-Bar": []string{"bar"},
			},
			setup: func(t *testing.T, ctx request.Context, mut *mocks2.URIMutatorMock, uri *url.URL) {
				t.Helper()

				mut.EXPECT().Mutate(mock.Anything).Return(uri, nil)

				ctx.AddHeaderForUpstream("X-User-ID", "someid")
				ctx.AddHeaderForUpstream("X-Custom", "somevalue")
				ctx.AddHeaderForUpstream("X-Forwarded-Method", http.MethodDelete)
				ctx.AddCookieForUpstream("my_cookie_1", "my_value_1")
				ctx.AddCookieForUpstream("my_cookie_2", "my_value_2")
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 8)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Contains(t, req.Header.Get("Cookie"), "my_cookie_1=my_value_1")
				assert.Contains(t, req.Header.Get("Cookie"), "my_cookie_2=my_value_2")
				assert.Equal(t, "for=192.0.2.1;host=foo.bar;proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "somevalue", req.Header.Get("X-Custom"))
				assert.Equal(t, "bar", req.Header.Get("X-Foo-Bar"))
				assert.Equal(t, http.MethodDelete, req.Header.Get("X-Forwarded-Method"))
				assert.Equal(t, "someid", req.Header.Get("X-User-Id"))
			},
		},
		{
			uc:             "Host header is set for upstream",
			upstreamCalled: true,
			setup: func(t *testing.T, ctx request.Context, mut *mocks2.URIMutatorMock, uri *url.URL) {
				t.Helper()

				mut.EXPECT().Mutate(mock.Anything).Return(uri, nil)

				ctx.AddHeaderForUpstream("Host", "bar.foo")
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "bar.foo")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 3)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "for=192.0.2.1;host=foo.bar;proto=https", req.Header.Get("Forwarded"))
			},
		},
		{
			uc:             "Only X-Forwarded-Proto header is present",
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-Proto": []string{"http"},
			},
			setup: func(t *testing.T, ctx request.Context, mut *mocks2.URIMutatorMock, uri *url.URL) {
				t.Helper()

				mut.EXPECT().Mutate(mock.Anything).Return(uri, nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 5)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "http", req.Header.Get("X-Forwarded-Proto"))
				assert.Equal(t, "foo.bar", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "192.0.2.1", req.Header.Get("X-Forwarded-For"))
			},
		},
		{
			uc:             "Only X-Forwarded-Host header is present",
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-Host": []string{"bar.foo"},
			},
			setup: func(t *testing.T, ctx request.Context, mut *mocks2.URIMutatorMock, uri *url.URL) {
				t.Helper()

				mut.EXPECT().Mutate(mock.Anything).Return(uri, nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 5)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
				assert.Equal(t, "bar.foo", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "192.0.2.1", req.Header.Get("X-Forwarded-For"))
			},
		},
		{
			uc:             "Only X-Forwarded-For header is present",
			upstreamCalled: true,
			headers: http.Header{
				"X-Forwarded-For": []string{"172.2.34.1"},
			},
			setup: func(t *testing.T, ctx request.Context, mut *mocks2.URIMutatorMock, uri *url.URL) {
				t.Helper()

				mut.EXPECT().Mutate(mock.Anything).Return(uri, nil)
			},
			assertRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 5)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "https", req.Header.Get("X-Forwarded-Proto"))
				assert.Equal(t, "foo.bar", req.Header.Get("X-Forwarded-Host"))
				assert.Equal(t, "172.2.34.1, 192.0.2.1", req.Header.Get("X-Forwarded-For"))
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			upstreamCalled := false
			req := httptest.NewRequest(http.MethodGet, "https://foo.bar/test", bytes.NewBufferString("Ping"))
			req.Header = tc.headers
			rw := httptest.NewRecorder()

			srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				upstreamCalled = true
				tc.assertRequest(t, req)
			}))
			defer srv.Close()

			ctx := newRequestContextFactory(nil, 100*time.Minute).Create(rw, req)
			mut := mocks2.NewURIMutatorMock(t)

			targetURL, err := url.Parse(srv.URL)
			require.NoError(t, err)

			tc.setup(t, ctx, mut, targetURL)

			// WHEN
			err = ctx.Finalize(mut)

			// THEN
			require.Equal(t, tc.upstreamCalled, upstreamCalled)
			if !tc.upstreamCalled {
				require.Error(t, err)
			}
		})
	}
}

func TestRequestContextHeaders(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequest(http.MethodHead, "https://foo.bar/test", nil)
	req.Header.Set("X-Foo-Bar", "foo")
	req.Header.Add("X-Foo-Bar", "bar")

	ctx := newRequestContextFactory(nil, 0).Create(nil, req)

	// WHEN
	headers := ctx.Request().Headers()

	// THEN
	require.Len(t, headers, 1)
	assert.Equal(t, "foo,bar", headers["X-Foo-Bar"])
}

func TestRequestContextHeader(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequest(http.MethodHead, "https://foo.bar/test", nil)
	req.Header.Set("X-Foo-Bar", "foo")
	req.Header.Add("X-Foo-Bar", "bar")
	req.Host = "bar.foo"

	ctx := newRequestContextFactory(nil, 0).Create(nil, req)

	// WHEN
	xFooBarValue := ctx.Request().Header("X-Foo-Bar")
	hostValue := ctx.Request().Header("Host")
	emptyValue := ctx.Request().Header("X-Not-Present")

	// THEN
	assert.Equal(t, "foo", xFooBarValue)
	assert.Equal(t, "bar.foo", hostValue)
	assert.Empty(t, emptyValue)
}

func TestRequestContextCookie(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequest(http.MethodHead, "https://foo.bar/test", nil)
	req.Header.Set("Cookie", "foo=bar; bar=baz")

	ctx := newRequestContextFactory(nil, 0).Create(nil, req)

	// WHEN
	value1 := ctx.Request().Cookie("bar")
	value2 := ctx.Request().Cookie("baz")

	// THEN
	assert.Equal(t, "baz", value1)
	assert.Empty(t, value2)
}

func TestRequestContextBody(t *testing.T) {
	t.Parallel()

	upstreamCalled := false

	req := httptest.NewRequest(http.MethodPost, "https://foo.bar/test", bytes.NewBufferString("Ping"))
	req.Header.Set("X-Custom", "foo")

	rw := httptest.NewRecorder()

	ctx := newRequestContextFactory(nil, 100*time.Minute).Create(rw, req)
	ctx.AddHeaderForUpstream("X-Foo", "bar")

	mut := mocks2.NewURIMutatorMock(t)

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		upstreamCalled = true

		assert.Contains(t, req.Host, "127.0.0.1")
		assert.Equal(t, http.MethodPost, req.Method)

		require.Len(t, req.Header, 5)
		assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
		assert.NotEmpty(t, req.Header.Get("Content-Length"))
		assert.Equal(t, "for=192.0.2.1;host=foo.bar;proto=https", req.Header.Get("Forwarded"))
		assert.Equal(t, "foo", req.Header.Get("X-Custom"))
		assert.Equal(t, "bar", req.Header.Get("X-Foo"))

		data, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		assert.Equal(t, "Ping", stringx.ToString(data))
	}))
	defer srv.Close()

	targetURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	mut.EXPECT().Mutate(mock.Anything).Return(targetURL, nil)

	// just consume body
	first := ctx.Request().Body()
	// there should be no difference
	second := ctx.Request().Body()

	// WHEN
	ctx.Finalize(mut)

	// THEN
	require.True(t, upstreamCalled)
	require.Equal(t, first, second)
}
