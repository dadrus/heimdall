// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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

package keyholder

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
)

type testKeyHolder []jose.JSONWebKey

func (t testKeyHolder) Keys() []jose.JSONWebKey { return t }

func TestRegistryKeys(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		keyHolder []KeyHolder
		assert    func(t *testing.T, keys []jose.JSONWebKey)
	}{
		"no key holders": {
			assert: func(t *testing.T, keys []jose.JSONWebKey) {
				t.Helper()

				assert.Empty(t, keys)
			},
		},
		"key holder without keys": {
			keyHolder: []KeyHolder{testKeyHolder{}},
			assert: func(t *testing.T, keys []jose.JSONWebKey) {
				t.Helper()

				assert.Empty(t, keys)
			},
		},
		"key holder with one key": {
			keyHolder: []KeyHolder{testKeyHolder{{KeyID: "test-1"}}},
			assert: func(t *testing.T, keys []jose.JSONWebKey) {
				t.Helper()

				assert.Equal(t, []jose.JSONWebKey{{KeyID: "test-1"}}, keys)
			},
		},
		"key holder with multiple keys": {
			keyHolder: []KeyHolder{testKeyHolder{{KeyID: "test-1"}, {KeyID: "test-2"}}},
			assert: func(t *testing.T, keys []jose.JSONWebKey) {
				t.Helper()

				assert.Equal(t, []jose.JSONWebKey{{KeyID: "test-1"}, {KeyID: "test-2"}}, keys)
			},
		},
		"multiple key holders, one with single key, one with multiple keys and one without keys": {
			keyHolder: []KeyHolder{
				testKeyHolder{{KeyID: "test-1"}, {KeyID: "test-2"}},
				testKeyHolder{},
				testKeyHolder{{KeyID: "test-3"}},
			},
			assert: func(t *testing.T, keys []jose.JSONWebKey) {
				t.Helper()

				assert.Equal(t, []jose.JSONWebKey{{KeyID: "test-1"}, {KeyID: "test-2"}, {KeyID: "test-3"}}, keys)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			reg := newRegistry()

			// WHEN
			for _, kh := range tc.keyHolder {
				reg.AddKeyHolder(kh)
			}

			// THEN
			tc.assert(t, reg.Keys())
		})
	}
}
