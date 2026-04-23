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

package errorhandlers

import (
	"io"
	"reflect"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeHeaderEntryHookFunc(t *testing.T) {
	t.Parallel()

	hook := DecodeHeaderEntryHookFunc()

	headerEntryValue := reflect.Zero(reflect.TypeFor[HeaderEntry]())
	someValue := reflect.Zero(reflect.TypeFor[io.Reader]())

	for uc, tc := range map[string]struct {
		data    any
		to      reflect.Value
		expErr  bool
		errText string
		assert  func(t *testing.T, decoded any)
	}{
		"source is not a map": {
			data: 42,
			to:   headerEntryValue,
			assert: func(t *testing.T, decoded any) {
				t.Helper()

				assert.Equal(t, 42, decoded)
			},
		},
		"target is not HeaderEntry": {
			data: map[string]any{"X-Test": "foo"},
			to:   someValue,
			assert: func(t *testing.T, decoded any) {
				t.Helper()

				assert.Equal(t, map[string]any{"X-Test": "foo"}, decoded)
			},
		},
		"invalid header configuration": {
			data:    map[string]any{"": ""},
			to:      headerEntryValue,
			expErr:  true,
			errText: "neither name nor value can be empty",
		},
		"decode map string any": {
			data: map[string]any{"X-Test": "foo"},
			to:   headerEntryValue,
			assert: func(t *testing.T, decoded any) {
				t.Helper()

				entry, ok := decoded.(HeaderEntry)
				require.True(t, ok)
				assert.Equal(t, "X-Test", entry.Name)

				rendered, err := entry.Value.Render(nil)
				require.NoError(t, err)
				assert.Equal(t, "foo", rendered)
			},
		},
		"decode map string": {
			data: map[string]string{"X-Test": "foo"},
			to:   headerEntryValue,
			assert: func(t *testing.T, decoded any) {
				t.Helper()

				entry, ok := decoded.(HeaderEntry)
				require.True(t, ok)
				assert.Equal(t, "X-Test", entry.Name)

				rendered, err := entry.Value.Render(nil)
				require.NoError(t, err)
				assert.Equal(t, "foo", rendered)
			},
		},
		"invalid map with multiple pairs": {
			data:    map[string]any{"X-Test": "foo", "X-Bar": "bar"},
			to:      headerEntryValue,
			expErr:  true,
			errText: "exactly one name/value pair",
		},
		"invalid key type": {
			data:    map[int]any{1: "foo"},
			to:      headerEntryValue,
			expErr:  true,
			errText: "header name must be a string",
		},
		"invalid value type": {
			data:    map[string]any{"X-Test": 42},
			to:      headerEntryValue,
			expErr:  true,
			errText: "value is not a string",
		},
		"invalid template value": {
			data:    map[string]any{"X-Test": "{{ .foo"},
			to:      headerEntryValue,
			expErr:  true,
			errText: "failed parsing value for header 'X-Test'",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			decoded, err := mapstructure.DecodeHookExec(hook, reflect.ValueOf(tc.data), tc.to)

			if tc.expErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.errText)

				return
			}

			require.NoError(t, err)
			tc.assert(t, decoded)
		})
	}
}
