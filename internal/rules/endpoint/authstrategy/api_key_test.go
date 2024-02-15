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

package authstrategy

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/endpoint"
)

func TestApplyApiKeyStrategy(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		strategy endpoint.AuthenticationStrategy
		assert   func(t *testing.T, err error, req *http.Request)
	}{
		{
			uc:       "header strategy",
			strategy: &APIKey{In: "header", Name: "Foo", Value: "Bar"},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "Bar", req.Header.Get("Foo"))
			},
		},
		{
			uc:       "cookie strategy",
			strategy: &APIKey{In: "cookie", Name: "Foo", Value: "Bar"},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)

				cookie, err := req.Cookie("Foo")
				require.NoError(t, err)
				assert.Equal(t, "Bar", cookie.Value)
			},
		},
		{
			uc:       "query strategy",
			strategy: &APIKey{In: "query", Name: "Foo", Value: "Bar"},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)

				query := req.URL.Query()
				assert.Len(t, query, 2)
				assert.Equal(t, "Bar", query.Get("Foo"))
				assert.Equal(t, "foo", query.Get("bar"))
			},
		},
		{
			uc:       "invalid strategy",
			strategy: &APIKey{In: "foo", Name: "Foo", Value: "Bar"},
			assert: func(t *testing.T, err error, _ *http.Request) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			req := &http.Request{
				Header: http.Header{},
				URL: &url.URL{
					Scheme:   "http",
					Host:     "foo.bar",
					Path:     "test",
					RawQuery: url.Values{"bar": []string{"foo"}}.Encode(),
				},
			}

			// WHEN
			err := tc.strategy.Apply(context.Background(), req)

			// THEN
			tc.assert(t, err, req)
		})
	}
}

func TestAPIKeyStrategyHash(t *testing.T) {
	t.Parallel()

	// GIVEN
	s1 := &APIKey{In: "header", Name: "Foo", Value: "Bar"}
	s2 := &APIKey{In: "cookie", Name: "Foo", Value: "Bar"}

	// WHEN
	hash1 := s1.Hash()
	hash2 := s2.Hash()

	// THEN
	assert.NotEmpty(t, hash1)
	assert.NotEmpty(t, hash2)
	assert.NotEqual(t, hash1, hash2)
}
