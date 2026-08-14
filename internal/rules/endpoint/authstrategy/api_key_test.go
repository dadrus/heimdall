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
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/endpoint"
)

func TestApplyApiKeyStrategy(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		strategy endpoint.AuthenticationStrategy
		assert   func(t *testing.T, err error, req *http.Request)
	}{
		"header strategy": {
			strategy: &APIKey{In: "header", Name: "Foo", Value: "Bar"},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "Bar", req.Header.Get("Foo"))
			},
		},
		"cookie strategy": {
			strategy: &APIKey{In: "cookie", Name: "Foo", Value: "Bar"},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)

				cookie, err := req.Cookie("Foo")
				require.NoError(t, err)
				assert.Equal(t, "Bar", cookie.Value)
			},
		},
		"query strategy": {
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
		"invalid strategy": {
			strategy: &APIKey{In: "foo", Name: "Foo", Value: "Bar"},
			assert: func(t *testing.T, err error, _ *http.Request) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "unsupported")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			original := &http.Request{
				Header: http.Header{
					"X-Test": []string{"test"},
				},
				URL: &url.URL{
					Scheme:   "http",
					Host:     "foo.bar",
					Path:     "test",
					RawQuery: url.Values{"bar": []string{"foo"}}.Encode(),
				},
			}

			req := *original

			// WHEN
			err := tc.strategy.Apply(&req)

			// THEN
			tc.assert(t, err, &req)

			assert.Equal(t, "test", original.Header.Get("X-Test"))
			assert.Empty(t, original.Header.Get("Foo"))

			query := original.URL.Query()
			assert.Len(t, query, 1)
			assert.Equal(t, "foo", query.Get("bar"))
			assert.Empty(t, query.Get("Foo"))

			_, err = original.Cookie("Foo")
			assert.ErrorIs(t, err, http.ErrNoCookie)
		})
	}
}

func TestAPIKeyStrategyHash(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		strategy1   *APIKey
		strategy2   *APIKey
		expectEqual bool
	}{
		"same configuration": {
			strategy1:   &APIKey{In: "header", Name: "Foo", Value: "Bar"},
			strategy2:   &APIKey{In: "header", Name: "Foo", Value: "Bar"},
			expectEqual: true,
		},
		"different location": {
			strategy1: &APIKey{In: "header", Name: "Foo", Value: "Bar"},
			strategy2: &APIKey{In: "cookie", Name: "Foo", Value: "Bar"},
		},
		"different name": {
			strategy1: &APIKey{In: "header", Name: "Foo", Value: "Bar"},
			strategy2: &APIKey{In: "header", Name: "Baz", Value: "Bar"},
		},
		"different value": {
			strategy1: &APIKey{In: "header", Name: "Foo", Value: "Bar"},
			strategy2: &APIKey{In: "header", Name: "Foo", Value: "Baz"},
		},
		"field boundaries are preserved": {
			strategy1: &APIKey{In: "header", Name: "a", Value: "bc"},
			strategy2: &APIKey{In: "header", Name: "ab", Value: "c"},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			hash1 := tc.strategy1.Hash()
			hash2 := tc.strategy2.Hash()

			// THEN
			assert.NotEmpty(t, hash1)
			assert.NotEmpty(t, hash2)

			if tc.expectEqual {
				assert.Equal(t, hash1, hash2)
			} else {
				assert.NotEqual(t, hash1, hash2)
			}
		})
	}
}
