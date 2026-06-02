// Copyright 2026 Dimitrij Drus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package pem

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets/provider"
)

func TestReadFile(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T) string
		assert func(t *testing.T, data []byte, err error)
	}{
		"reads file contents": {
			setup: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "data.pem")

				require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))

				return path
			},
			assert: func(t *testing.T, data []byte, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []byte("content"), data)
			},
		},
		"fails to read contents": {
			setup: func(t *testing.T) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "missing.pem")
			},
			assert: func(t *testing.T, _ []byte, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "failed to read")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			path := tc.setup(t)

			data, err := readFile(path)

			tc.assert(t, data, err)
		})
	}
}
