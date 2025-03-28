// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package redis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestDecodeCredentialsHookFunc(t *testing.T) {
	t.Parallel()

	type Type struct {
		Credentials credentials `mapstructure:"credentials"`
	}

	testDir := t.TempDir()

	cf1, err := os.Create(filepath.Join(testDir, "credentials1.yaml"))
	require.NoError(t, err)

	_, err = cf1.WriteString(`
  username: oof
  password: rab
`)
	require.NoError(t, err)

	cf2, err := os.Create(filepath.Join(testDir, "credentials2.yaml"))
	require.NoError(t, err)

	_, err = cf2.WriteString(`
  username: oof
`)
	require.NoError(t, err)

	cf3, err := os.Create(filepath.Join(testDir, "credentials3.yaml"))
	require.NoError(t, err)

	_, err = cf3.WriteString(`
  password: rab
`)
	require.NoError(t, err)

	cf4, err := os.Create(filepath.Join(testDir, "credentials4.yaml"))
	require.NoError(t, err)

	_, err = cf4.WriteString(`
  foo: bar
  bar: foo
`)
	require.NoError(t, err)

	// du to a bug in the linter
	for uc, tc := range map[string]struct {
		config []byte
		assert func(t *testing.T, err error, creds credentials)
	}{
		"static structured credentials with all fields": {
			config: []byte(`
credentials:
  username: foo
  password: bar
`),
			assert: func(t *testing.T, err error, creds credentials) {
				t.Helper()

				require.NoError(t, err)
				require.IsType(t, &staticCredentials{}, creds)

				sc := creds.(*staticCredentials) // nolint: forcetypeassert
				assert.Equal(t, "foo", sc.Username)
				assert.Equal(t, "bar", sc.Password)
			},
		},
		"static structured credentials with username only": {
			config: []byte(`
credentials:
  username: foo
`),
			assert: func(t *testing.T, err error, creds credentials) {
				t.Helper()

				require.NoError(t, err)
				require.IsType(t, &staticCredentials{}, creds)

				sc := creds.(*staticCredentials) // nolint: forcetypeassert
				assert.Equal(t, "foo", sc.Username)
				assert.Empty(t, sc.Password)
			},
		},
		"static structured credentials with password only": {
			config: []byte(`
credentials:
  password: bar
`),
			assert: func(t *testing.T, err error, creds credentials) {
				t.Helper()

				require.NoError(t, err)
				require.IsType(t, &staticCredentials{}, creds)

				sc := creds.(*staticCredentials) // nolint: forcetypeassert
				assert.Empty(t, sc.Username)
				assert.Equal(t, "bar", sc.Password)
			},
		},
		"existing externally managed credentials with all fields": {
			config: []byte(`credentials: { path: ` + cf1.Name() + `}`),
			assert: func(t *testing.T, err error, creds credentials) {
				t.Helper()

				require.NoError(t, err)
				require.IsType(t, &fileCredentials{}, creds)

				sc := creds.(*fileCredentials) // nolint: forcetypeassert
				assert.Equal(t, cf1.Name(), sc.Path)
				assert.Equal(t, "oof", sc.creds.Username)
				assert.Equal(t, "rab", sc.creds.Password)
			},
		},
		"existing externally managed credentials with username only": {
			config: []byte(`credentials: { path: ` + cf2.Name() + `}`),
			assert: func(t *testing.T, err error, creds credentials) {
				t.Helper()

				require.NoError(t, err)
				require.IsType(t, &fileCredentials{}, creds)

				sc := creds.(*fileCredentials) // nolint: forcetypeassert
				assert.Equal(t, cf2.Name(), sc.Path)
				assert.Equal(t, "oof", sc.creds.Username)
				assert.Empty(t, sc.creds.Password)
			},
		},
		"existing externally managed credentials with password only": {
			config: []byte(`credentials: { path: ` + cf3.Name() + `}`),
			assert: func(t *testing.T, err error, creds credentials) {
				t.Helper()

				require.NoError(t, err)
				require.IsType(t, &fileCredentials{}, creds)

				sc := creds.(*fileCredentials) // nolint: forcetypeassert
				assert.Equal(t, cf3.Name(), sc.Path)
				assert.Empty(t, sc.creds.Username)
				assert.Equal(t, "rab", sc.creds.Password)
			},
		},
		"not existing externally managed credentials": {
			config: []byte(`credentials: { path: ` + testDir + "/foo.bar }"),
			assert: func(t *testing.T, err error, _ credentials) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "no such file")
			},
		},
		"existing externally managed credentials file with bad content": {
			config: []byte(`credentials: { path: ` + cf4.Name() + `}`),
			assert: func(t *testing.T, err error, _ credentials) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "unmarshal errors")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					decodeCredentialsHookFunc,
				),
				Result: &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			tc.assert(t, err, typ.Credentials)
		})
	}
}
