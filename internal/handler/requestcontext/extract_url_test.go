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

package requestcontext

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractURL(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		configureRequest func(t *testing.T, req *http.Request)
		assert           func(t *testing.T, extracted url.URL, originalPathContainsEncodedSlash bool, err error)
	}{
		"X-Forwarded-Proto set": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Proto", "https")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted url.URL, _ bool, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "https", extracted.Scheme)
				assert.Equal(t, "heimdall.test.local", extracted.Host)
				assert.Equal(t, "/test%2Ffoo/bar/%5Bval%5D", extracted.EscapedPath())
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extracted.Query())
			},
		},
		"X-Forwarded-Host set": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Host", "foobar")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted url.URL, _ bool, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "http", extracted.Scheme)
				assert.Equal(t, "foobar", extracted.Host)
				assert.Equal(t, "/test%2Ffoo/bar/%5Bval%5D", extracted.EscapedPath())
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extracted.Query())
			},
		},
		"X-Forwarded-Host is normalized to lowercase": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Host", "FoObAr.Example.COM:8443")
			},
			assert: func(t *testing.T, extracted url.URL, _ bool, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foobar.example.com:8443", extracted.Host)
			},
		},
		"request host fallback is normalized to lowercase": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Host = "FooBar.Example.Local:9443"
			},
			assert: func(t *testing.T, extracted url.URL, _ bool, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "foobar.example.local:9443", extracted.Host)
			},
		},
		"X-Forwarded-Path is ignored": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Path", "/bar%2Ftest/foo/%5Bval%5D")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted url.URL, originalPathContainsEncodedSlash bool, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, originalPathContainsEncodedSlash)

				assert.Equal(t, "http", extracted.Scheme)
				assert.Equal(t, "heimdall.test.local", extracted.Host)
				assert.Equal(t, "/test%2Ffoo/bar/%5Bval%5D", extracted.EscapedPath())
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extracted.Query())
			},
		},
		"empty X-Forwarded-Uri results in request URL usage": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "")
				req.URL.RawQuery = "foo=bar"
			},
			assert: func(t *testing.T, extracted url.URL, originalPathContainsEncodedSlash bool, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, originalPathContainsEncodedSlash)

				assert.Equal(t, "/test%2Ffoo/bar/%5Bval%5D", extracted.EscapedPath())
				assert.Equal(t, "foo=bar", extracted.RawQuery)
			},
		},
		"request query is ignored for X-Forwarded-Uri without query": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "/admin")
				req.URL.RawQuery = "foo=bar"
			},
			assert: func(t *testing.T, extracted url.URL, originalPathContainsEncodedSlash bool, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, originalPathContainsEncodedSlash)

				assert.Equal(t, "/admin", extracted.EscapedPath())
				assert.Empty(t, extracted.RawQuery)
			},
		},
		"X-Forwarded-Uri in absolute form with a path": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "http://example.com/admin")
			},
			assert: func(t *testing.T, extracted url.URL, _ bool, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "/admin", extracted.EscapedPath())
				assert.Equal(t, "heimdall.test.local", extracted.Host)
			},
		},
		"X-Forwarded-Uri set without dot segments": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "/bar%2Ftest/foo/%5Bval%5D?bar=foo")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted url.URL, originalPathContainsEncodedSlash bool, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, originalPathContainsEncodedSlash)

				assert.Equal(t, "http", extracted.Scheme)
				assert.Equal(t, "heimdall.test.local", extracted.Host)
				assert.Equal(t, "/bar%2Ftest/foo/%5Bval%5D", extracted.EscapedPath())
				assert.Equal(t, url.Values{"bar": []string{"foo"}}, extracted.Query())
			},
		},
		"X-Forwarded-Uri with leading double slash is not read as an authority": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "//admin/settings?bar=foo")
			},
			assert: func(t *testing.T, extracted url.URL, _ bool, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "heimdall.test.local", extracted.Host)
				assert.Equal(t, "/admin/settings", extracted.EscapedPath())
				assert.Equal(t, url.Values{"bar": []string{"foo"}}, extracted.Query())
			},
		},
		"X-Forwarded-Uri original slash is erased by normalization": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "/api/a%2fb/../c")
			},
			assert: func(t *testing.T, extracted url.URL, originalPathContainsEncodedSlash bool, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, originalPathContainsEncodedSlash)
				assert.Equal(t, "/api/c", extracted.EscapedPath())
			},
		},
		"X-Forwarded-Uri query escapes do not count as path slashes": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "/public?next=%2F")
			},
			assert: func(t *testing.T, extracted url.URL, originalPathContainsEncodedSlash bool, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, originalPathContainsEncodedSlash)
				assert.Equal(t, "/public", extracted.EscapedPath())
				assert.Equal(t, "next=%2F", extracted.RawQuery)
			},
		},
		"X-Forwarded-Uri set with dot segments": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "/bar/../test/foo/%5Bval%5D?bar=foo")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted url.URL, originalPathContainsEncodedSlash bool, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, originalPathContainsEncodedSlash)

				assert.Equal(t, "http", extracted.Scheme)
				assert.Equal(t, "heimdall.test.local", extracted.Host)
				assert.Equal(t, "/test/foo/%5Bval%5D", extracted.EscapedPath())
				assert.Equal(t, url.Values{"bar": []string{"foo"}}, extracted.Query())
			},
		},
		"X-Forwarded-Uri rejects encoded dot segments": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "/bar/%2e.%2ftest/foo/%5Bval%5D?bar=foo")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted url.URL, originalPathContainsEncodedSlash bool, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrInvalidRequestURI)
				assert.Equal(t, url.URL{}, extracted)
				assert.False(t, originalPathContainsEncodedSlash)
			},
		},
		"X-Forwarded-Uri rejects encoded dot segments if another byte requires escaping": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "/admin/%2e%2e%2fpublic/x|?bar=foo")
			},
			assert: func(t *testing.T, _ url.URL, _ bool, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrInvalidRequestURI)
			},
		},
		"X-Forwarded-Uri retains encoded slash if another byte requires escaping": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "/files/a%2Fb|")
			},
			assert: func(t *testing.T, extracted url.URL, originalPathContainsEncodedSlash bool, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, originalPathContainsEncodedSlash)

				assert.Equal(t, "/files/a/b|", extracted.Path)
				assert.Equal(t, "/files/a%2Fb%7C", extracted.RawPath)
				assert.Equal(t, "/files/a%2Fb%7C", extracted.EscapedPath())
			},
		},
		"invalid escape in X-Forwarded-Uri": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "/admin/%zz")
			},
			assert: func(t *testing.T, _ url.URL, _ bool, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrInvalidRequestURI)
			},
		},
		"pathless X-Forwarded-Uri": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "http://admin")
			},
			assert: func(t *testing.T, _ url.URL, _ bool, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrInvalidRequestURI)
			},
		},
		"literal fragment delimiter in X-Forwarded-Uri": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "/metrics#fragment")
			},
			assert: func(t *testing.T, _ url.URL, _ bool, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrInvalidRequestURI)
			},
		},
		"literal fragment delimiter in request line with valid forwarded URI": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.RequestURI = "/metrics#fragment"
				req.Header.Set("X-Forwarded-Uri", "/metrics")
			},
			assert: func(t *testing.T, _ url.URL, _ bool, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrInvalidRequestURI)
			},
		},
		"Request path is used and ends with a slash": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.URL.Path = "/bar/baz/"
				req.URL.RawPath = "/bar/baz/"
			},
			assert: func(t *testing.T, extracted url.URL, _ bool, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "http", extracted.Scheme)
				assert.Equal(t, "heimdall.test.local", extracted.Host)
				assert.Equal(t, "/bar/baz/", extracted.EscapedPath())
				assert.Empty(t, extracted.Query())
			},
		},
		"Request path is used which is a slash": {
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.URL.Path = "/"
				req.URL.RawPath = "/"
			},
			assert: func(t *testing.T, extracted url.URL, _ bool, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "http", extracted.Scheme)
				assert.Equal(t, "heimdall.test.local", extracted.Host)
				assert.Equal(t, "/", extracted.EscapedPath())
				assert.Empty(t, extracted.Query())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"http://heimdall.test.local/test%2Ffoo/bar/%5Bval%5D",
				nil,
			)
			require.NoError(t, err)

			tc.configureRequest(t, req)

			// WHEN
			extracted, originalPathContainsEncodedSlash, err := extractURL(req)

			// THEN
			tc.assert(t, extracted, originalPathContainsEncodedSlash, err)
		})
	}
}
