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

package parser

import (
	"errors"
	"io"
	"os"
	"testing"

	"github.com/knadh/koanf/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x"
)

func TestKoanfFromYaml(t *testing.T) {
	t.Setenv("FOO", "BAR")
	t.Setenv("COMPLEX", "{ first: foo, second: bar }")

	for uc, tc := range map[string]struct {
		config    []byte
		validator ConfigSyntaxValidator
		chmod     func(t *testing.T, file *os.File)
		assert    func(t *testing.T, err error, kanf *koanf.Koanf)
	}{
		"valid content without env substitution": {
			config: []byte(`
some_string: foo
someint: 3
nested1:
  somebool: true
  some_string: bar
nested_2:
  - somebool: false
    some_string: baz
`),
			validator: func(_ io.Reader) error { return nil },
			assert: func(t *testing.T, err error, konf *koanf.Koanf) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", konf.Get("some_string"))
				assert.Equal(t, 3, konf.Get("someint"))
				assert.Equal(t, "bar", konf.Get("nested1.some_string"))
				assert.Equal(t, true, konf.Get("nested1.somebool")) //nolint:testifylint
				assert.Len(t, konf.Get("nested_2"), 1)
				assert.Contains(t, konf.Get("nested_2"), map[string]any{"some_string": "baz", "somebool": false})
			},
		},
		"failed validation": {
			config:    []byte(`some_string: foo`),
			validator: func(_ io.Reader) error { return errors.New("test error") },
			assert: func(t *testing.T, err error, konf *koanf.Koanf) {
				t.Helper()

				require.Error(t, err)
				require.Contains(t, err.Error(), "test error")
			},
		},
		"valid content with env substitution and templates": {
			config: []byte(`
some_string: ${FOO}
someint: 3
nested1:
  somebool: true
  some_string: bar
nested_2:
  - somebool: false
    some_string: '{ "name": {{ if $user_name }}{{ quote $user_name }}{{ else }}{{ quote $email }}{{ end }} }'
`),
			validator: func(_ io.Reader) error { return nil },
			assert: func(t *testing.T, err error, konf *koanf.Koanf) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "BAR", konf.Get("some_string"))
				assert.Equal(t, 3, konf.Get("someint"))
				assert.Equal(t, "bar", konf.Get("nested1.some_string"))
				assert.Equal(t, true, konf.Get("nested1.somebool")) //nolint:testifylint
				assert.Len(t, konf.Get("nested_2"), 1)
				assert.Contains(t, konf.Get("nested_2"),
					map[string]any{
						"some_string": `{ "name": {{ if $user_name }}{{ quote $user_name }}{{ else }}{{ quote $email }}{{ end }} }`,
						"somebool":    false,
					})
			},
		},
		"valid content with complex env substitution": {
			config:    []byte(`complex: ${COMPLEX}`),
			validator: func(_ io.Reader) error { return nil },
			assert: func(t *testing.T, err error, konf *koanf.Koanf) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", konf.Get("complex.first"))
				assert.Equal(t, "bar", konf.Get("complex.second"))
			},
		},
		"invalid yaml content": {
			config:    []byte("foobar"),
			validator: func(cfgSrc io.Reader) error { return nil },
			assert: func(t *testing.T, err error, _ *koanf.Koanf) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to load")
			},
		},
		"invalid yaml env substitution": {
			config:    []byte("${:}"),
			validator: func(_ io.Reader) error { return nil },
			assert: func(t *testing.T, err error, _ *koanf.Koanf) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to parse")
			},
		},
		"can't read content": {
			config:    []byte(`foo: bar`),
			validator: func(_ io.Reader) error { return nil },
			chmod: func(t *testing.T, file *os.File) {
				t.Helper()

				err := file.Chmod(0o222)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, err error, _ *koanf.Koanf) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to read")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			chmod := x.IfThenElse(tc.chmod != nil, tc.chmod, func(t *testing.T, _ *os.File) { t.Helper() })

			tempFile, err := os.CreateTemp(t.TempDir(), "config-test-*")
			require.NoError(t, err)

			defer tempFile.Close()

			fileName := tempFile.Name()

			_, err = tempFile.Write(tc.config)
			require.NoError(t, err)

			chmod(t, tempFile)

			// WHEN
			konf, err := koanfFromYaml(fileName, tc.validator)

			// THEN
			tc.assert(t, err, konf)
		})
	}
}
