// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package heimdall

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHeaders(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		values http.Header
		assert func(t *testing.T, headers Headers)
	}{
		"with headers": {
			values: http.Header{"X-Foo": {"bar"}},
			assert: func(t *testing.T, headers Headers) {
				t.Helper()

				assert.Equal(t, http.Header{"X-Foo": {"bar"}}, headers.values)
				assert.Nil(t, headers.cache)
			},
		},
		"with nil headers": {
			assert: func(t *testing.T, headers Headers) {
				t.Helper()

				assert.Nil(t, headers.values)
				assert.Nil(t, headers.cache)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			headers := NewHeaders(tc.values)

			tc.assert(t, headers)
		})
	}
}

func TestHeadersGet(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		headers *Headers
		name    string
		assert  func(t *testing.T, headers *Headers, value string)
	}{
		"existing header": {
			headers: &Headers{values: http.Header{"X-Foo": {"bar"}}},
			name:    "X-Foo",
			assert: func(t *testing.T, headers *Headers, value string) {
				t.Helper()

				assert.Equal(t, "bar", value)
				require.Contains(t, headers.cache, "X-Foo")
				assert.Equal(t, "bar", headers.cache["X-Foo"])
				assert.Equal(t, "bar", headers.Get("X-Foo"))
				assert.Equal(t, http.Header{"X-Foo": {"bar"}}, headers.values)
			},
		},
		"header name is case insensitive": {
			headers: &Headers{values: http.Header{"X-Foo": {"bar"}}},
			name:    "x-foo",
			assert: func(t *testing.T, headers *Headers, value string) {
				t.Helper()

				assert.Equal(t, "bar", value)
				require.Contains(t, headers.cache, "x-foo")
				assert.Equal(t, "bar", headers.cache["x-foo"])
				assert.Equal(t, http.Header{"X-Foo": {"bar"}}, headers.values)
			},
		},
		"multiple values are joined": {
			headers: &Headers{values: http.Header{"X-Foo": {"bar", "baz"}}},
			name:    "X-Foo",
			assert: func(t *testing.T, headers *Headers, value string) {
				t.Helper()

				assert.Equal(t, "bar,baz", value)
				require.Contains(t, headers.cache, "X-Foo")
				assert.Equal(t, "bar,baz", headers.cache["X-Foo"])
				assert.Equal(t, http.Header{"X-Foo": {"bar", "baz"}}, headers.values)
			},
		},
		"missing header": {
			headers: &Headers{values: http.Header{"X-Foo": {"bar"}}},
			name:    "X-Bar",
			assert: func(t *testing.T, headers *Headers, value string) {
				t.Helper()

				assert.Empty(t, value)
				require.Contains(t, headers.cache, "X-Bar")
				assert.Empty(t, headers.cache["X-Bar"])
				assert.Equal(t, http.Header{"X-Foo": {"bar"}}, headers.values)
			},
		},
		"nil headers": {
			headers: &Headers{},
			name:    "X-Foo",
			assert: func(t *testing.T, headers *Headers, value string) {
				t.Helper()

				assert.Empty(t, value)
				require.Contains(t, headers.cache, "X-Foo")
				assert.Empty(t, headers.cache["X-Foo"])
			},
		},
		"nil receiver": {
			name: "X-Foo",
			assert: func(t *testing.T, _ *Headers, value string) {
				t.Helper()

				assert.Empty(t, value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			value := tc.headers.Get(tc.name)

			tc.assert(t, tc.headers, value)
		})
	}
}
