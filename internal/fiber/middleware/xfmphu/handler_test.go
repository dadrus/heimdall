// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

package xfmphu

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x"
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
		URL              string
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
		{
			uc:  "Empty path",
			URL: "http://heimdall.test.local",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set(xSentFrom, nginxIngressAgent)
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T) {
				t.Helper()

				require.True(t, testAppCalled)
				assert.Equal(t, "GET", extractedMethod)
				assert.Equal(t, "http", extractedURL.Scheme)
				assert.Equal(t, "heimdall.test.local", extractedURL.Host)
				assert.Empty(t, extractedURL.Path)
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extractedURL.Query())
			},
		},
		{
			uc:  "NGINX workaround test 1",
			URL: "http://heimdall.test.local//test",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set(xSentFrom, nginxIngressAgent)
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
			uc:  "NGINX workaround test 2",
			URL: "http://heimdall.test.local/test",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set(xSentFrom, nginxIngressAgent)
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
			reqURL := x.IfThenElse(len(tc.URL) != 0, tc.URL, "http://heimdall.test.local/test")
			testAppCalled = false
			extractedURL = nil
			extractedMethod = ""

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, reqURL, nil)
			require.NoError(t, err)

			tc.configureRequest(t, req)

			// WHEN
			resp, err := app.Test(req, -1)
			require.NoError(t, err)
			defer resp.Body.Close()

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

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
				"http://heimdall.test.local/test", nil)
			require.NoError(t, err)

			tc.configureRequest(t, req)

			// WHEN
			resp, err := app.Test(req, -1)
			require.NoError(t, err)
			defer resp.Body.Close()

			// THEN
			tc.assert(t)
		})
	}
}
