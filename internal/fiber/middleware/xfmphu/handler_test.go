package xfmphu

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddlewareApplicationWithoutConfiguredTrustedProxy(t *testing.T) {
	t.Parallel()

	var (
		extractedURL    *url.URL
		extractedMethod string
		testAppCalled   bool
	)

	app := fiber.New(fiber.Config{
		EnableTrustedProxyCheck: true,
	})

	defer app.Shutdown() // nolint: errcheck

	app.All("/*", New(), func(ctx *fiber.Ctx) error {
		testAppCalled = true
		extractedURL = RequestURL(ctx.UserContext())
		extractedMethod = RequestMethod(ctx.UserContext())

		return nil
	})

	for _, tc := range []struct {
		uc               string
		configureRequest func(t *testing.T, req *http.Request)
		assert           func(t *testing.T)
	}{
		{
			uc: "X-Forwarded-Method set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set(xForwardedMethod, "POST")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T) {
				t.Helper()

				require.True(t, testAppCalled)
				assert.Equal(t, "GET", extractedMethod)
				assert.Equal(t, "http", extractedURL.Scheme)
				assert.Equal(t, "heimdall.test.local", extractedURL.Host)
				assert.Equal(t, "/test", extractedURL.Path)
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extractedURL.Query())
			},
		},
		{
			uc: "X-Forwarded-Proto set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Proto", "https")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T) {
				t.Helper()

				require.True(t, testAppCalled)
				assert.Equal(t, "GET", extractedMethod)
				assert.Equal(t, "http", extractedURL.Scheme)
				assert.Equal(t, "heimdall.test.local", extractedURL.Host)
				assert.Equal(t, "/test", extractedURL.Path)
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extractedURL.Query())
			},
		},
		{
			uc: "X-Forwarded-Host set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Host", "foobar")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T) {
				t.Helper()

				require.True(t, testAppCalled)
				assert.Equal(t, "GET", extractedMethod)
				assert.Equal(t, "http", extractedURL.Scheme)
				assert.Equal(t, "heimdall.test.local", extractedURL.Host)
				assert.Equal(t, "/test", extractedURL.Path)
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extractedURL.Query())
			},
		},
		{
			uc: "X-Forwarded-Path set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Path", "/foobar")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T) {
				t.Helper()

				require.True(t, testAppCalled)
				assert.Equal(t, "GET", extractedMethod)
				assert.Equal(t, "http", extractedURL.Scheme)
				assert.Equal(t, "heimdall.test.local", extractedURL.Host)
				assert.Equal(t, "/test", extractedURL.Path)
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extractedURL.Query())
			},
		},
		{
			uc: "X-Forwarded-Uri set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "https://foo.bar/bar?bar=foo")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T) {
				t.Helper()

				require.True(t, testAppCalled)
				assert.Equal(t, "GET", extractedMethod)
				assert.Equal(t, "http", extractedURL.Scheme)
				assert.Equal(t, "heimdall.test.local", extractedURL.Host)
				assert.Equal(t, "/test", extractedURL.Path)
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extractedURL.Query())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			testAppCalled = false
			extractedURL = nil
			extractedMethod = ""

			req, err := http.NewRequest("GET", "http://heimdall.test.local/test", nil)
			require.NoError(t, err)

			tc.configureRequest(t, req)

			// WHEN
			_, err = app.Test(req, -1)
			require.NoError(t, err)

			// THEN
			tc.assert(t)
		})
	}
}

func TestMiddlewareApplicationWithConfiguredTrustedProxy(t *testing.T) {
	t.Parallel()

	var (
		extractedURL    *url.URL
		extractedMethod string
		testAppCalled   bool
	)

	app := fiber.New(fiber.Config{
		EnableTrustedProxyCheck: true,
		TrustedProxies:          []string{"0.0.0.0/0"},
	})

	defer app.Shutdown() // nolint: errcheck

	app.All("/*", New(), func(ctx *fiber.Ctx) error {
		testAppCalled = true
		extractedURL = RequestURL(ctx.UserContext())
		extractedMethod = RequestMethod(ctx.UserContext())

		return nil
	})

	for _, tc := range []struct {
		uc               string
		configureRequest func(t *testing.T, req *http.Request)
		assert           func(t *testing.T)
	}{
		{
			uc: "X-Forwarded-Method set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set(xForwardedMethod, "POST")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T) {
				t.Helper()

				require.True(t, testAppCalled)
				assert.Equal(t, "POST", extractedMethod)
				assert.Equal(t, "http", extractedURL.Scheme)
				assert.Equal(t, "heimdall.test.local", extractedURL.Host)
				assert.Equal(t, "/test", extractedURL.Path)
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extractedURL.Query())
			},
		},
		{
			uc: "X-Forwarded-Proto set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Proto", "https")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T) {
				t.Helper()

				require.True(t, testAppCalled)
				assert.Equal(t, "GET", extractedMethod)
				assert.Equal(t, "https", extractedURL.Scheme)
				assert.Equal(t, "heimdall.test.local", extractedURL.Host)
				assert.Equal(t, "/test", extractedURL.Path)
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extractedURL.Query())
			},
		},
		{
			uc: "X-Forwarded-Host set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Host", "foobar")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T) {
				t.Helper()

				require.True(t, testAppCalled)
				assert.Equal(t, "GET", extractedMethod)
				assert.Equal(t, "http", extractedURL.Scheme)
				assert.Equal(t, "foobar", extractedURL.Host)
				assert.Equal(t, "/test", extractedURL.Path)
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extractedURL.Query())
			},
		},
		{
			uc: "X-Forwarded-Path set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Path", "foobar")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T) {
				t.Helper()

				require.True(t, testAppCalled)
				assert.Equal(t, "GET", extractedMethod)
				assert.Equal(t, "http", extractedURL.Scheme)
				assert.Equal(t, "heimdall.test.local", extractedURL.Host)
				assert.Equal(t, "foobar", extractedURL.Path)
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extractedURL.Query())
			},
		},
		{
			uc: "X-Forwarded-Uri set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "https://foo.bar/bar?bar=foo")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T) {
				t.Helper()

				require.True(t, testAppCalled)
				assert.Equal(t, "GET", extractedMethod)
				assert.Equal(t, "https", extractedURL.Scheme)
				assert.Equal(t, "foo.bar", extractedURL.Host)
				assert.Equal(t, "/bar", extractedURL.Path)
				assert.Equal(t, url.Values{"bar": []string{"foo"}}, extractedURL.Query())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			testAppCalled = false
			extractedURL = nil
			extractedMethod = ""

			req, err := http.NewRequest("GET", "http://heimdall.test.local/test", nil)
			require.NoError(t, err)

			tc.configureRequest(t, req)

			// WHEN
			_, err = app.Test(req, -1)
			require.NoError(t, err)

			// THEN
			tc.assert(t)
		})
	}
}
