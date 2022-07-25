package proxyheader

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddlewareApplicationWithoutConfiguredTrustedProxy(t *testing.T) {
	t.Parallel()

	var (
		valueXForwardedFor, valueForwarded string
		testAppCalled                      bool
	)

	app := fiber.New(fiber.Config{
		EnableTrustedProxyCheck: true,
	})
	app.Use(New())

	defer app.Shutdown() // nolint: errcheck

	app.Get("test", func(ctx *fiber.Ctx) error {
		testAppCalled = true
		valueXForwardedFor = ctx.Get(headerXForwardedFor)
		valueForwarded = ctx.Get(headerForwarded)

		return nil
	})

	for _, tc := range []struct {
		uc               string
		configureRequest func(t *testing.T, req *http.Request)
		assert           func(t *testing.T)
	}{
		{
			uc: "X-Forwarded-For header sent",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set(headerXForwardedFor, "1.1.1.1")
			},
			assert: func(t *testing.T) {
				t.Helper()

				assert.True(t, testAppCalled)

				receivedValues := strings.Split(valueXForwardedFor, ",")
				require.Len(t, receivedValues, 1)
				assert.Equal(t, strings.TrimSpace(receivedValues[0]), "0.0.0.0")

				receivedValues = strings.Split(valueForwarded, ",")
				require.Len(t, receivedValues, 1)
				assert.Equal(t, strings.TrimSpace(receivedValues[0]), "for=0.0.0.0;proto=http")
			},
		},
		{
			uc: "Forwarded header sent",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set(headerForwarded, "for=1.1.1.1;proto=http")
			},
			assert: func(t *testing.T) {
				t.Helper()

				assert.True(t, testAppCalled)

				receivedValues := strings.Split(valueXForwardedFor, ",")
				require.Len(t, receivedValues, 1)
				assert.Equal(t, strings.TrimSpace(receivedValues[0]), "0.0.0.0")

				receivedValues = strings.Split(valueForwarded, ",")
				require.Len(t, receivedValues, 1)
				assert.Equal(t, strings.TrimSpace(receivedValues[0]), "for=0.0.0.0;proto=http")
			},
		},
		{
			uc: "X-Forwarded-For and Forwarded header sent",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set(headerXForwardedFor, "1.1.1.1")
				req.Header.Set(headerForwarded, "for=1.1.1.1;proto=http")
			},
			assert: func(t *testing.T) {
				t.Helper()

				assert.True(t, testAppCalled)

				receivedValues := strings.Split(valueXForwardedFor, ",")
				require.Len(t, receivedValues, 1)
				assert.Equal(t, strings.TrimSpace(receivedValues[0]), "0.0.0.0")

				receivedValues = strings.Split(valueForwarded, ",")
				require.Len(t, receivedValues, 1)
				assert.Equal(t, strings.TrimSpace(receivedValues[0]), "for=0.0.0.0;proto=http")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			testAppCalled = false
			valueXForwardedFor = ""
			valueForwarded = ""

			req, err := http.NewRequest("GET", "/test", nil)
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
		valueXForwardedFor, valueForwarded string
		testAppCalled                      bool
	)

	app := fiber.New(fiber.Config{
		TrustedProxies:          []string{"0.0.0.0/0"},
		EnableTrustedProxyCheck: true,
	})
	app.Use(New())

	defer app.Shutdown() // nolint: errcheck

	app.Get("test", func(ctx *fiber.Ctx) error {
		testAppCalled = true
		valueXForwardedFor = ctx.Get(headerXForwardedFor)
		valueForwarded = ctx.Get(headerForwarded)

		return nil
	})

	for _, tc := range []struct {
		uc               string
		configureRequest func(t *testing.T, req *http.Request)
		assert           func(t *testing.T)
	}{
		{
			uc: "only X-Forwarded-For header sent",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set(headerXForwardedFor, "1.1.1.1")
			},
			assert: func(t *testing.T) {
				t.Helper()

				assert.True(t, testAppCalled)

				receivedValues := strings.Split(valueForwarded, ",")
				require.Len(t, receivedValues, 1)
				assert.Equal(t, strings.TrimSpace(receivedValues[0]), "for=0.0.0.0;proto=http")

				receivedValues = strings.Split(valueXForwardedFor, ",")
				require.Len(t, receivedValues, 2)
				assert.Equal(t, strings.TrimSpace(receivedValues[0]), "1.1.1.1")
				assert.Equal(t, strings.TrimSpace(receivedValues[1]), "0.0.0.0")
			},
		},
		{
			uc: "only Forwarded header sent",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set(headerForwarded, "for=1.1.1.1;proto=http")
			},
			assert: func(t *testing.T) {
				t.Helper()

				assert.True(t, testAppCalled)

				receivedValues := strings.Split(valueXForwardedFor, ",")
				require.Len(t, receivedValues, 1)
				assert.Equal(t, strings.TrimSpace(receivedValues[0]), "0.0.0.0")

				receivedValues = strings.Split(valueForwarded, ",")
				require.Len(t, receivedValues, 2)
				assert.Equal(t, strings.TrimSpace(receivedValues[0]), "for=1.1.1.1;proto=http")
				assert.Equal(t, strings.TrimSpace(receivedValues[1]), "for=0.0.0.0;proto=http")
			},
		},
		{
			uc: "X-Forwarded-For and Forwarded header sent",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set(headerXForwardedFor, "1.1.1.1")
				req.Header.Set(headerForwarded, "for=1.1.1.1;proto=http")
			},
			assert: func(t *testing.T) {
				t.Helper()

				assert.True(t, testAppCalled)

				receivedValues := strings.Split(valueXForwardedFor, ",")
				require.Len(t, receivedValues, 2)
				assert.Equal(t, strings.TrimSpace(receivedValues[0]), "1.1.1.1")
				assert.Equal(t, strings.TrimSpace(receivedValues[1]), "0.0.0.0")

				receivedValues = strings.Split(valueForwarded, ",")
				require.Len(t, receivedValues, 2)
				assert.Equal(t, strings.TrimSpace(receivedValues[0]), "for=1.1.1.1;proto=http")
				assert.Equal(t, strings.TrimSpace(receivedValues[1]), "for=0.0.0.0;proto=http")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			testAppCalled = false
			valueXForwardedFor = ""
			valueForwarded = ""

			req, err := http.NewRequest("GET", "/test", nil)
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
