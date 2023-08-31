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

	_interface "github.com/dadrus/heimdall/internal/handler/proxy2/interface"
	"github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/errorhandler/mocks"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

func TestRequestContextError(t *testing.T) {
	t.Parallel()

	testErr := errors.New("test error")
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "https://foo.bar/test", nil)

	eh := mocks.NewErrorHandlerMock(t)
	eh.EXPECT().HandleError(rw, req, testErr)

	factory := newRequestContextFactory(eh, nil, 0)
	rc := factory.Create(rw, req)

	// WHEN -> THEN expectations are met
	rc.Error(testErr)
}

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
		setup          func(t *testing.T, ctx _interface.RequestContext, eh *mocks.ErrorHandlerMock)
		assert         func(t *testing.T, req *http.Request)
	}{
		{
			"error was present, forwarding aborted",
			false,
			http.Header{},
			func(t *testing.T, ctx _interface.RequestContext, eh *mocks.ErrorHandlerMock) {
				t.Helper()

				err := errors.New("test error")
				ctx.SetPipelineError(err)

				eh.EXPECT().HandleError(mock.Anything, mock.Anything, err)
			},
			func(t *testing.T, req *http.Request) {
				t.Helper()

				require.Len(t, req.Header, 3)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "for=192.0.2.1;proto=https", req.Header.Get("Forwarded"))
			},
		},
		{
			"no headers set",
			true,
			http.Header{},
			func(t *testing.T, ctx _interface.RequestContext, eh *mocks.ErrorHandlerMock) { t.Helper() },
			func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 3)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "for=192.0.2.1;proto=https", req.Header.Get("Forwarded"))
			},
		},
		{
			"all X-Forwarded-* and Forwarded headers present",
			true,
			http.Header{
				"X-Forwarded-Proto":  []string{"https"},
				"X-Forwarded-Host":   []string{"bar.foo"},
				"X-Forwarded-Path":   []string{"/foobar"},
				"X-Forwarded-Uri":    []string{"/barfoo?foo=bar"},
				"X-Forwarded-Method": []string{http.MethodPatch},
				"X-Forwarded-For":    []string{"127.0.0.2, 192.168.12.126"},
				"Forwarded":          []string{"proto=http;for=127.0.0.3, proto=http;for=192.168.12.127"},
			},
			func(t *testing.T, ctx _interface.RequestContext, eh *mocks.ErrorHandlerMock) { t.Helper() },
			func(t *testing.T, req *http.Request) {
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
			"only X-Forwarded-Method and Forwarded headers are present",
			true,
			http.Header{
				"X-Forwarded-Method": []string{http.MethodPost},
				"Forwarded":          []string{"proto=http;for=127.0.0.3, proto=http;for=192.168.12.127"},
			},
			func(t *testing.T, ctx _interface.RequestContext, eh *mocks.ErrorHandlerMock) { t.Helper() },
			func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodPost, req.Method)

				require.Len(t, req.Header, 3)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "proto=http;for=127.0.0.3, proto=http;for=192.168.12.127, for=192.0.2.1;proto=https", req.Header.Get("Forwarded"))
			},
		},
		{
			"only custom headers and results from rule execution are present",
			true,
			http.Header{
				"X-Foo-Bar": []string{"bar"},
			},
			func(t *testing.T, ctx _interface.RequestContext, eh *mocks.ErrorHandlerMock) {
				t.Helper()

				ctx.AddHeaderForUpstream("X-User-ID", "someid")
				ctx.AddHeaderForUpstream("X-Custom", "somevalue")
				ctx.AddHeaderForUpstream("X-Forwarded-Method", http.MethodDelete)
				ctx.AddCookieForUpstream("my_cookie_1", "my_value_1")
				ctx.AddCookieForUpstream("my_cookie_2", "my_value_2")
			},
			func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Contains(t, req.Host, "127.0.0.1")
				assert.Equal(t, http.MethodGet, req.Method)

				require.Len(t, req.Header, 8)
				assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
				assert.NotEmpty(t, req.Header.Get("Content-Length"))
				assert.Equal(t, "my_cookie_1=my_value_1; my_cookie_2=my_value_2", req.Header.Get("Cookie"))
				assert.Equal(t, "for=192.0.2.1;proto=https", req.Header.Get("Forwarded"))
				assert.Equal(t, "somevalue", req.Header.Get("X-Custom"))
				assert.Equal(t, "bar", req.Header.Get("X-Foo-Bar"))
				assert.Equal(t, http.MethodDelete, req.Header.Get("X-Forwarded-Method"))
				assert.Equal(t, "someid", req.Header.Get("X-User-Id"))
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			upstreamCalled := false
			req := httptest.NewRequest(http.MethodGet, "https://foo.bar/test", bytes.NewBufferString("Ping"))
			req.Header = tc.headers
			rw := httptest.NewRecorder()
			eh := mocks.NewErrorHandlerMock(t)
			ctx := newRequestContextFactory(eh, nil, 100*time.Minute).Create(rw, req)
			tc.setup(t, ctx, eh)

			srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				upstreamCalled = true
				tc.assert(t, req)
			}))
			defer srv.Close()

			targetURL, err := url.Parse(srv.URL)
			require.NoError(t, err)

			// WHEN
			ctx.Finalize(targetURL)

			// THEN
			require.Equal(t, tc.upstreamCalled, upstreamCalled)
		})
	}
}

func TestRequestContextHeaders(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequest(http.MethodHead, "https://foo.bar/test", nil)
	req.Header.Set("X-Foo-Bar", "foo")
	req.Header.Add("X-Foo-Bar", "bar")

	ctx := newRequestContextFactory(nil, nil, 0).Create(nil, req)

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

	ctx := newRequestContextFactory(nil, nil, 0).Create(nil, req)

	// WHEN
	value := ctx.Request().Header("X-Foo-Bar")

	// THEN
	assert.Equal(t, "foo", value)
}

func TestRequestContextCookie(t *testing.T) {
	t.Parallel()

	// GIVEN
	req := httptest.NewRequest(http.MethodHead, "https://foo.bar/test", nil)
	req.Header.Set("Cookie", "foo=bar; bar=baz")

	ctx := newRequestContextFactory(nil, nil, 0).Create(nil, req)

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
	eh := mocks.NewErrorHandlerMock(t)

	ctx := newRequestContextFactory(eh, nil, 100*time.Minute).Create(rw, req)
	ctx.AddHeaderForUpstream("X-Foo", "bar")

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		upstreamCalled = true

		assert.Contains(t, req.Host, "127.0.0.1")
		assert.Equal(t, http.MethodPost, req.Method)

		require.Len(t, req.Header, 5)
		assert.NotEmpty(t, req.Header.Get("Accept-Encoding"))
		assert.NotEmpty(t, req.Header.Get("Content-Length"))
		assert.Equal(t, "for=192.0.2.1;proto=https", req.Header.Get("Forwarded"))
		assert.Equal(t, "foo", req.Header.Get("X-Custom"))
		assert.Equal(t, "bar", req.Header.Get("X-Foo"))

		data, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		assert.Equal(t, "Ping", stringx.ToString(data))
	}))
	defer srv.Close()

	targetURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	// just consume body
	first := ctx.Request().Body()
	// there should be no difference
	second := ctx.Request().Body()

	// WHEN
	ctx.Finalize(targetURL)

	// THEN
	require.True(t, upstreamCalled)
	require.Equal(t, first, second)
}
