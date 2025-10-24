// Copyright 2025 Dimitrij Drus <dadrus@gmx.de>
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

package converter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConverterConvert(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		date           []byte
		format         string
		desiredVersion string
		assert         func(t *testing.T, err error, result []byte)
	}{
		"decoding failed": {
			date: []byte("foo"),
			assert: func(t *testing.T, err error, _ []byte) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrConversion)
				require.ErrorContains(t, err, "failed to decode")
			},
		},
		"ruleset is already in the expected version": {
			date:           []byte("version: 1alpha4"),
			format:         "application/yaml",
			desiredVersion: "1alpha4",
			assert: func(t *testing.T, err error, _ []byte) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrConversion)
				require.ErrorContains(t, err, "ruleset is already in the expected version")
			},
		},
		"cannot convert from v1alpha4 to v1alpha3": {
			date:           []byte("version: 1alpha4"),
			format:         "application/yaml",
			desiredVersion: "v1alpha3",
			assert: func(t *testing.T, err error, _ []byte) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrConversion)
				require.ErrorContains(t, err, "unexpected target ruleset version: v1alpha3")
			},
		},
		"cannot convert from v1beta1 to v1alpha3": {
			date:           []byte("version: 1beta1"),
			format:         "application/yaml",
			desiredVersion: "v1alpha3",
			assert: func(t *testing.T, err error, _ []byte) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrConversion)
				require.ErrorContains(t, err, "unexpected target ruleset version: v1alpha3")
			},
		},
		"unexpected source version": {
			date:           []byte("version: foo"),
			format:         "application/yaml",
			desiredVersion: "v1alpha4",
			assert: func(t *testing.T, err error, _ []byte) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrConversion)
				require.ErrorContains(t, err, "unexpected source ruleset version: foo")
			},
		},
		"successful conversion from v1alpha4 to v1beta1": {
			date: []byte(`
version: 1alpha4
rules:
  - id: public-access
    allow_encoded_slashes: on
    match: 
      routes:
        - path: /pub/*baz
          path_params:
            - name: baz
              value: "*foo*"
              type: glob
      methods: [GET, POST]
      hosts:
        - value: foo.bar
          type: exact
        - value: "*.foo"
          type: wildcard
      scheme: https
    forward_to:
      host: foo-app.local:8080
    execute:
      - authorizer: allow_all_requests
    on_error:
      - error_handler: default
`),
			format:         "application/yaml",
			desiredVersion: "1beta1",
			assert: func(t *testing.T, err error, result []byte) {
				t.Helper()

				require.NoError(t, err)
				assert.YAMLEq(t, `
version: 1beta1
rules:
  - id: public-access
    allow_encoded_slashes: on
    match: 
      routes:
        - path: /pub/*baz
          path_params:
            - name: baz
              value: "*foo*"
              type: glob
      methods: [GET, POST]
      hosts:
        - foo.bar
        - "*.foo"
      scheme: https
    forward_to:
      host: foo-app.local:8080
    execute:
      - authorizer: allow_all_requests
    on_error:
      - error_handler: default
`, string(result))
			},
		},
		"successful conversion from v1beta1 to v1alpha4": {
			date: []byte(`
version: 1beta1
rules:
  - id: public-access
    allow_encoded_slashes: on
    match: 
      routes:
        - path: /pub/*baz
          path_params:
            - name: baz
              value: "*foo*"
              type: glob
      methods: [GET, POST]
      hosts:
        - foo.bar
        - "*.foo"
      scheme: https
    forward_to:
      host: foo-app.local:8080
    execute:
      - authorizer: allow_all_requests
    on_error:
      - error_handler: default
`),
			format:         "application/yaml",
			desiredVersion: "1alpha4",
			assert: func(t *testing.T, err error, result []byte) {
				t.Helper()

				require.NoError(t, err)
				assert.YAMLEq(t, `
version: 1alpha4
rules:
  - id: public-access
    allow_encoded_slashes: on
    match: 
      routes:
        - path: /pub/*baz
          path_params:
            - name: baz
              value: "*foo*"
              type: glob
      methods: [GET, POST]
      hosts:
        - value: foo.bar
          type: wildcard
        - value: "*.foo"
          type: wildcard
      scheme: https
    forward_to:
      host: foo-app.local:8080
    execute:
      - authorizer: allow_all_requests
    on_error:
      - error_handler: default
`, string(result))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			conv := New(tc.desiredVersion)

			// WHEN
			res, err := conv.Convert(tc.date, tc.format)

			// THEN
			tc.assert(t, err, res)
		})
	}
}
