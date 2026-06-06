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

package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets/provider"
)

func TestLoadStore(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		path   func(t *testing.T) string
		assert func(t *testing.T, err error, s store)
	}{
		"loads jwks file": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.jwks")

				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				raw, err := json.Marshal(jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   key,
							KeyID: "rsa-key",
						},
						{
							Key:       []byte("0123456789abcdef"),
							KeyID:     "hmac-key",
							Algorithm: "HS256",
						},
					},
				})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, raw, 0o600))

				return path
			},
			assert: func(t *testing.T, err error, store store) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, store)

				secrets, err := store.getSecretSet(t.Context(), provider.Selector{})
				require.NoError(t, err)
				require.Len(t, secrets, 2)

				assert.Equal(t, "rsa-key", secrets[0].Selector())
				assert.Equal(t, "hmac-key", secrets[1].Selector())
			},
		},
		"returns configuration error if file cannot be read": {
			path: func(t *testing.T) string {
				t.Helper()

				return "missing.jwks"
			},
			assert: func(t *testing.T, err error, _ store) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "failed to read jwks file")
			},
		},
		"returns configuration error for malformed jwks file": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.jwks")

				require.NoError(t, os.WriteFile(path, []byte(`{`), 0o600))

				return path
			},
			assert: func(t *testing.T, err error, _ store) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "failed to decode jwks file")
			},
		},
		"returns configuration error for jwks without key material": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.jwks")

				raw, err := json.Marshal(jose.JSONWebKeySet{})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, raw, 0o600))

				return path
			},
			assert: func(t *testing.T, err error, _ store) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "no key material present")
			},
		},
		"returns configuration error from key store validation": {
			path: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "keys.jwks")

				raw, err := json.Marshal(jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{
						{
							Key:   []byte("too-short"),
							KeyID: "short-key",
						},
					},
				})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, raw, 0o600))

				return path
			},
			assert: func(t *testing.T, err error, _ store) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "contains key material shorter than 16 bytes")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			store, err := loadStore(tc.path(t))

			tc.assert(t, err, store)
		})
	}
}
