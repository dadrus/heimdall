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

package pipeline

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewResult(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		payload any
		assert  func(t *testing.T, result *Result)
	}{
		"with payload": {
			payload: map[string]any{"foo": "bar"},
			assert: func(t *testing.T, result *Result) {
				t.Helper()

				require.NotNil(t, result)
				assert.Equal(t, map[string]any{"foo": "bar"}, result.Payload)
				assert.False(t, result.hasHeaders)
			},
		},
		"with nil payload": {
			assert: func(t *testing.T, result *Result) {
				t.Helper()

				require.NotNil(t, result)
				assert.Nil(t, result.Payload)
				assert.False(t, result.hasHeaders)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			result := NewResult(tc.payload)

			tc.assert(t, result)
		})
	}
}

func TestNewResultWithHeaders(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		payload any
		headers http.Header
		assert  func(t *testing.T, result *Result)
	}{
		"with headers": {
			payload: map[string]any{"foo": "bar"},
			headers: http.Header{"X-Foo": {"bar", "baz"}},
			assert: func(t *testing.T, result *Result) {
				t.Helper()

				require.NotNil(t, result)
				assert.Equal(t, map[string]any{"foo": "bar"}, result.Payload)
				assert.True(t, result.hasHeaders)
				assert.Equal(t, "bar,baz", result.Header("x-foo"))
			},
		},
		"with nil headers": {
			payload: "foo",
			assert: func(t *testing.T, result *Result) {
				t.Helper()

				require.NotNil(t, result)
				assert.Equal(t, "foo", result.Payload)
				assert.True(t, result.hasHeaders)
				assert.Empty(t, result.Header("X-Foo"))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			result := NewResultWithHeaders(tc.payload, tc.headers)

			tc.assert(t, result)
		})
	}
}

func TestResultHeader(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		result *Result
		name   string
		assert func(t *testing.T, value string)
	}{
		"existing header": {
			result: NewResultWithHeaders("foo", http.Header{"X-Foo": {"bar"}}),
			name:   "X-Foo",
			assert: func(t *testing.T, value string) {
				t.Helper()

				assert.Equal(t, "bar", value)
			},
		},
		"header name is case insensitive": {
			result: NewResultWithHeaders("foo", http.Header{"X-Foo": {"bar"}}),
			name:   "x-foo",
			assert: func(t *testing.T, value string) {
				t.Helper()

				assert.Equal(t, "bar", value)
			},
		},
		"multiple values are joined": {
			result: NewResultWithHeaders("foo", http.Header{"X-Foo": {"bar", "baz"}}),
			name:   "X-Foo",
			assert: func(t *testing.T, value string) {
				t.Helper()

				assert.Equal(t, "bar,baz", value)
			},
		},
		"missing header": {
			result: NewResultWithHeaders("foo", http.Header{"X-Foo": {"bar"}}),
			name:   "X-Bar",
			assert: func(t *testing.T, value string) {
				t.Helper()

				assert.Empty(t, value)
			},
		},
		"result without headers": {
			result: NewResult("foo"),
			name:   "X-Foo",
			assert: func(t *testing.T, value string) {
				t.Helper()

				assert.Empty(t, value)
			},
		},
		"nil receiver": {
			name: "X-Foo",
			assert: func(t *testing.T, value string) {
				t.Helper()

				assert.Empty(t, value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			value := tc.result.Header(tc.name)

			tc.assert(t, value)
		})
	}
}

func TestResultMarshalJSON(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		result *Result
		assert func(t *testing.T, data []byte, err error)
	}{
		"without headers": {
			result: NewResult(map[string]any{"foo": "bar"}),
			assert: func(t *testing.T, data []byte, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.JSONEq(t, `{"payload":{"foo":"bar"}}`, string(data))
			},
		},
		"with headers": {
			result: NewResultWithHeaders(
				map[string]any{"foo": "bar"},
				http.Header{"X-Foo": {"bar", "baz"}},
			),
			assert: func(t *testing.T, data []byte, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.JSONEq(t, `{"headers":{"X-Foo":["bar","baz"]},"payload":{"foo":"bar"}}`, string(data))
			},
		},
		"with explicitly nil headers": {
			result: NewResultWithHeaders("foo", nil),
			assert: func(t *testing.T, data []byte, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.JSONEq(t, `{"headers":null,"payload":"foo"}`, string(data))
			},
		},
		"nil receiver": {
			assert: func(t *testing.T, data []byte, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.JSONEq(t, `null`, string(data))
			},
		},
		"unsupported payload": {
			result: NewResult(make(chan struct{})),
			assert: func(t *testing.T, _ []byte, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			data, err := tc.result.MarshalJSON()

			tc.assert(t, data, err)
		})
	}
}

func TestResultUnmarshalJSON(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		result *Result
		data   string
		assert func(t *testing.T, result *Result, err error)
	}{
		"without headers": {
			result: &Result{},
			data:   `{"payload":{"foo":"bar"}}`,
			assert: func(t *testing.T, result *Result, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, map[string]any{"foo": "bar"}, result.Payload)
				assert.False(t, result.hasHeaders)
				assert.Empty(t, result.Header("X-Foo"))

				data, err := result.MarshalJSON()
				require.NoError(t, err)
				assert.JSONEq(t, `{"payload":{"foo":"bar"}}`, string(data))
			},
		},
		"with headers": {
			result: &Result{},
			data:   `{"headers":{"X-Foo":["bar","baz"]},"payload":"foo"}`,
			assert: func(t *testing.T, result *Result, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", result.Payload)
				assert.True(t, result.hasHeaders)
				assert.Equal(t, "bar,baz", result.Header("x-foo"))

				data, err := result.MarshalJSON()
				require.NoError(t, err)
				assert.JSONEq(t, `{"headers":{"X-Foo":["bar","baz"]},"payload":"foo"}`, string(data))
			},
		},
		"with explicitly null headers": {
			result: &Result{},
			data:   `{"headers":null,"payload":"foo"}`,
			assert: func(t *testing.T, result *Result, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", result.Payload)
				assert.True(t, result.hasHeaders)
				assert.Empty(t, result.Header("X-Foo"))

				data, err := result.MarshalJSON()
				require.NoError(t, err)
				assert.JSONEq(t, `{"headers":null,"payload":"foo"}`, string(data))
			},
		},
		"previous state is reset": {
			result: &Result{
				Payload: "old",
				headers: Headers{
					values: http.Header{"X-Foo": {"bar"}},
					cache:  map[string]string{"X-Foo": "bar"},
				},
				hasHeaders: true,
			},
			data: `{"payload":"new"}`,
			assert: func(t *testing.T, result *Result, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "new", result.Payload)
				assert.False(t, result.hasHeaders)
				assert.Nil(t, result.headers.values)
				assert.Nil(t, result.headers.cache)
				assert.Empty(t, result.Header("X-Foo"))
			},
		},
		"malformed json": {
			result: &Result{},
			data:   `{"payload":`,
			assert: func(t *testing.T, _ *Result, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		"invalid headers": {
			result: &Result{},
			data:   `{"headers":"foo","payload":"bar"}`,
			assert: func(t *testing.T, _ *Result, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			err := json.Unmarshal([]byte(tc.data), tc.result)

			tc.assert(t, tc.result, err)
		})
	}
}
