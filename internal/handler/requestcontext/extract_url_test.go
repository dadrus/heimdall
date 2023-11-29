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
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractURL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc               string
		configureRequest func(t *testing.T, req *http.Request)
		assert           func(t *testing.T, extracted *url.URL)
	}{
		{
			uc: "X-Forwarded-Proto set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Proto", "https")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted *url.URL) {
				t.Helper()

				assert.Equal(t, "https", extracted.Scheme)
				assert.Equal(t, "heimdall.test.local", extracted.Host)
				assert.Equal(t, "/test%2Ffoo/bar/%5Bval%5D", extracted.EscapedPath())
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extracted.Query())
			},
		},
		{
			uc: "X-Forwarded-Host set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Host", "foobar")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted *url.URL) {
				t.Helper()

				assert.Equal(t, "http", extracted.Scheme)
				assert.Equal(t, "foobar", extracted.Host)
				assert.Equal(t, "/test%2Ffoo/bar/%5Bval%5D", extracted.EscapedPath())
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extracted.Query())
			},
		},
		{
			uc: "X-Forwarded-Path set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Path", "/bar%2Ftest/foo/%5Bval%5D")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted *url.URL) {
				t.Helper()

				assert.Equal(t, "http", extracted.Scheme)
				assert.Equal(t, "heimdall.test.local", extracted.Host)
				assert.Equal(t, "/bar%2Ftest/foo/%5Bval%5D", extracted.EscapedPath())
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extracted.Query())
			},
		},
		{
			uc: "X-Forwarded-Uri set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "/bar%2Ftest/foo/%5Bval%5D?bar=foo")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted *url.URL) {
				t.Helper()

				assert.Equal(t, "http", extracted.Scheme)
				assert.Equal(t, "heimdall.test.local", extracted.Host)
				assert.Equal(t, "/bar%2Ftest/foo/%5Bval%5D", extracted.EscapedPath())
				assert.Equal(t, url.Values{"bar": []string{"foo"}}, extracted.Query())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			req, err := http.NewRequestWithContext(
				context.TODO(),
				http.MethodGet,
				"http://heimdall.test.local/test%2Ffoo/bar/%5Bval%5D",
				nil,
			)
			require.NoError(t, err)

			tc.configureRequest(t, req)

			// WHEN
			extracted := extractURL(req)

			// THEN
			tc.assert(t, extracted)
		})
	}
}
