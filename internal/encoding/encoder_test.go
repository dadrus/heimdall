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

package encoding

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncode(t *testing.T) {
	t.Parallel()

	type TestType struct {
		Foo string `json:"foo" yaml:"foo"`
	}

	for uc, tc := range map[string]struct {
		contentType string
		assert      func(t *testing.T, err error, result string)
	}{
		"unknown contentType": {
			contentType: "unknown",
			assert: func(t *testing.T, err error, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "unsupported content type: unknown")
			},
		},
		"contentType is application/json": {
			contentType: "application/json",
			assert: func(t *testing.T, err error, result string) {
				t.Helper()

				require.NoError(t, err)
				assert.JSONEq(t, `{ "foo": "bar" }`, result)
			},
		},
		"contentType is application/yaml": {
			contentType: "application/yaml",
			assert: func(t *testing.T, err error, result string) {
				t.Helper()

				require.NoError(t, err)
				assert.YAMLEq(t, `foo: bar`, result)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			obj := TestType{Foo: "bar"}
			buf := &bytes.Buffer{}
			encoder := NewEncoder(WithTargetContentType(tc.contentType))

			// WHEN
			err := encoder.Encode(obj, buf)

			// THEN
			tc.assert(t, err, buf.String())
		})
	}
}
