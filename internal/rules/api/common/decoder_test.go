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

package common

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestDecode(t *testing.T) {
	t.Setenv("FOO_BAR_BAZ", "bla")

	type TestType struct {
		Foo string `json:"foo" yaml:"foo"`
	}

	for uc, tc := range map[string]struct {
		opts   []DecoderOption
		data   []byte
		assert func(t *testing.T, err error, typ TestType)
	}{
		"unknown content type": {
			opts: []DecoderOption{WithSourceContentType("foo")},
			assert: func(t *testing.T, err error, _ TestType) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "unsupported content type: foo")
			},
		},
		"env var substitution fails": {
			opts: []DecoderOption{
				WithSourceContentType("application/json"),
				WithEnvVarsSubstitution(true),
			},
			data: []byte(`{"foo":"${FOO"}`),
			assert: func(t *testing.T, err error, _ TestType) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "substitution of env")
			},
		},
		"decoding failed due to EOF": {
			opts: []DecoderOption{
				WithSourceContentType("application/json"),
			},
			assert: func(t *testing.T, err error, _ TestType) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, io.EOF)
			},
		},
		"decoding failed due to malformed data": {
			opts: []DecoderOption{
				WithSourceContentType("application/json"),
			},
			data: []byte(`{ "foo": `),
			assert: func(t *testing.T, err error, _ TestType) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "parsing of object failed")
			},
		},
		"decoding failed due to unused fields": {
			opts: []DecoderOption{
				WithSourceContentType("application/json"),
				WithErrorOnUnused(true),
			},
			data: []byte(`{ "bar": "baz" }`),
			assert: func(t *testing.T, err error, _ TestType) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "decoding of object failed")
			},
		},
		"validation fails": {
			opts: []DecoderOption{
				WithSourceContentType("application/json"),
				WithErrorOnUnused(true),
				WithValidator(ValidatorFunc(func(interface{}) error { return errors.New("test error") })),
			},
			data: []byte(`{ "foo": "baz" }`),
			assert: func(t *testing.T, err error, _ TestType) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "test error")
			},
		},
		"successful decoding of a json object with env vars": {
			opts: []DecoderOption{
				WithSourceContentType("application/json"),
				WithEnvVarsSubstitution(true),
			},
			data: []byte(`{ "foo": "${FOO_BAR_BAZ}" }`),
			assert: func(t *testing.T, err error, typ TestType) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "bla", typ.Foo)
			},
		},
		"successful decoding of a yaml object without env vars": {
			opts: []DecoderOption{
				WithSourceContentType("application/yaml"),
			},
			data: []byte(`foo: baz`),
			assert: func(t *testing.T, err error, typ TestType) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "baz", typ.Foo)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			var res TestType

			decoder := NewDecoder(tc.opts...)

			// WHEN
			err := decoder.Decode(&res, bytes.NewBuffer(tc.data))

			// THEN
			tc.assert(t, err, res)
		})
	}
}
