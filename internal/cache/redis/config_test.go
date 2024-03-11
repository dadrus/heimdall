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

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileCredentialsReload(t *testing.T) {
	t.Parallel()

	// GIVEN
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
username: foo
password: bar
`)
	require.NoError(t, err)

	cf3, err := os.Create(filepath.Join(testDir, "credentials3.yaml"))
	require.NoError(t, err)

	_, err = cf3.WriteString(`
  foo: bar
  bar: foo
`)
	require.NoError(t, err)

	fc := &fileCredentials{Path: cf1.Name()}

	// WHEN
	err = fc.load()

	// THEN
	require.NoError(t, err)

	assert.Equal(t, "oof", fc.creds.Username)
	assert.Equal(t, "rab", fc.creds.Password)

	// WHEN
	fc.Path = cf2.Name()
	fc.OnChanged(log.Logger)

	// THEN
	assert.Equal(t, "foo", fc.creds.Username)
	assert.Equal(t, "bar", fc.creds.Password)

	// WHEN
	fc.Path = cf3.Name()
	fc.OnChanged(log.Logger)

	// THEN
	assert.Equal(t, "foo", fc.creds.Username)
	assert.Equal(t, "bar", fc.creds.Password)
}
