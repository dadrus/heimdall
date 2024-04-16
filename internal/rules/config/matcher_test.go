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

package config

import (
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathUnmarshalJSON(t *testing.T) {
	t.Parallel()

	type Typ struct {
		Path Path `json:"path"`
	}

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, path *Path)
	}{
		{
			uc:     "specified as string",
			config: []byte(`{ "path": "foo.bar" }`),
			assert: func(t *testing.T, err error, path *Path) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo.bar", path.Expression)
				assert.Empty(t, path.Glob)
				assert.Empty(t, path.Regex)
			},
		},
		{
			uc: "specified as structured type with invalid json structure",
			config: []byte(`{
  "path": {
    expression: foo
  }
}`),
			assert: func(t *testing.T, err error, _ *Path) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid character")
			},
		},
		{
			uc: "specified as structured type without expression",
			config: []byte(`{
  "path": {
    "regex": "foo"
  }
}`),
			assert: func(t *testing.T, err error, _ *Path) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "'expression' is a required field")
			},
		},
		{
			uc: "specified as structured type with everything specified",
			config: []byte(`{
  "path": {
    "expression": "foo.bar",
    "glob": "**.css",
    "regex": ".*\\.css"
  }
}`),
			assert: func(t *testing.T, err error, path *Path) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo.bar", path.Expression)
				assert.Equal(t, "**.css", path.Glob)
				assert.Equal(t, ".*\\.css", path.Regex)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			var typ Typ

			// WHEN
			err := json.Unmarshal(tc.config, &typ)

			// THEN
			tc.assert(t, err, &typ.Path)
		})
	}
}
