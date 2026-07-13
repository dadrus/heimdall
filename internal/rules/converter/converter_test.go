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

	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/validation"
)

func TestConverterConvert(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		data           []byte
		format         string
		desiredVersion string
		assert         func(t *testing.T, err error, result []byte)
	}{
		"decoding failed": {
			data: []byte("foo"),
			assert: func(t *testing.T, err error, _ []byte) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrConversion)
				require.ErrorContains(t, err, "failed to decode")
			},
		},
		"ruleset is already in the expected version": {
			data:           []byte("version: 1alpha4"),
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
			data:           []byte("version: 1alpha4"),
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
			data:           []byte("version: 1beta1"),
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
			data:           []byte("version: foo"),
			format:         "application/yaml",
			desiredVersion: "v1alpha4",
			assert: func(t *testing.T, err error, _ []byte) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrConversion)
				require.ErrorContains(t, err, "unexpected source ruleset version: foo")
			},
		},
		"v1beta1 ruleset without HTTP matcher cannot be converted": {
			data: []byte(`
version: 1beta1
rules:
  - id: public-access
    match: {}
    execute:
      - authorizer: allow_all_requests
`),
			format:         "application/yaml",
			desiredVersion: "1alpha4",
			assert: func(t *testing.T, err error, _ []byte) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrConversion)
				require.ErrorContains(t, err, "failed to decode 1beta1 ruleset")
			},
		},
		"v1alpha4 ruleset with glob host matcher cannot be converted": {
			data: []byte(`
version: 1alpha4
rules:
  - id: public-access
    match:
      routes:
        - path: /pub/**
      hosts:
        - value: "*.foo"
          type: glob
    execute:
      - authorizer: allow_all_requests
`),
			format:         "application/yaml",
			desiredVersion: "1beta1",
			assert: func(t *testing.T, err error, _ []byte) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrConversion)
				require.ErrorContains(t, err, `host matcher of type "glob"`)
				require.ErrorContains(t, err, `rule "public-access"`)
				require.ErrorContains(t, err, "cannot be converted automatically")
			},
		},
		"v1alpha4 ruleset with regex host matcher cannot be converted": {
			data: []byte(`
version: 1alpha4
rules:
  - id: public-access
    match:
      routes:
        - path: /pub/**
      hosts:
        - value: "^api[0-9]+[.]example[.]com$"
          type: regex
    execute:
      - authorizer: allow_all_requests
`),
			format:         "application/yaml",
			desiredVersion: "1beta1",
			assert: func(t *testing.T, err error, _ []byte) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrConversion)
				require.ErrorContains(t, err, `host matcher of type "regex"`)
				require.ErrorContains(t, err, `rule "public-access"`)
				require.ErrorContains(t, err, "cannot be converted automatically")
			},
		},
		"successful conversion from v1alpha4 to v1beta1": {
			data: []byte(`
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
      http:
        paths:
          - path: /pub/*baz
            captures:
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
		"successful conversion from v1alpha4 to v1beta1 without backend": {
			data: []byte(`
version: 1alpha4
rules:
  - id: public-access
    match:
      routes:
        - path: /pub/**
    execute:
      - authorizer: allow_all_requests
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
    match:
      http:
        paths:
          - path: /pub/**
    execute:
      - authorizer: allow_all_requests
`, string(result))
			},
		},
		"successful conversion from v1beta1 to v1alpha4": {
			data: []byte(`
version: 1beta1
rules:
  - id: public-access
    allow_encoded_slashes: on
    match:
      http:
        paths:
          - path: /pub/*baz
            captures:
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
		"successful conversion from v1beta1 to v1alpha4 without backend": {
			data: []byte(`
version: 1beta1
rules:
  - id: public-access
    match:
      http:
        paths:
          - path: /pub/**
    execute:
      - authorizer: allow_all_requests
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
    match:
      routes:
        - path: /pub/**
    execute:
      - authorizer: allow_all_requests
`, string(result))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			validator, err := validation.NewValidator()
			require.NoError(t, err)

			conv := New(tc.desiredVersion, encoding.ValidatorFunc(validator.ValidateStruct))

			// WHEN
			var (
				res           []byte
				conversionErr error
			)

			require.NotPanics(t, func() {
				res, conversionErr = conv.Convert(tc.data, tc.format)
			})

			// THEN
			tc.assert(t, conversionErr, res)
		})
	}
}
