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
	"testing"

	"github.com/knadh/koanf/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestKoanfFromStruct(t *testing.T) {
	t.Parallel()

	type TestConfigWithUppercase struct {
		ThisIsMissingAKoanfTag string
	}

	type TestNestedConfig struct {
		SomeBool   bool   `koanf:"somebool"`
		SomeString string `koanf:"some_string"`
	}

	type TestConfig struct {
		SomeString string             `koanf:"some_string"`
		SomeInt    int                `koanf:"someint"`
		Nested1    TestNestedConfig   `koanf:"nested1"`
		Nested2    []TestNestedConfig `koanf:"nested_2"`
	}

	for _, tc := range []struct {
		uc     string
		conf   any
		assert func(t *testing.T, err error, konf *koanf.Koanf)
	}{
		{
			uc: "missing koanf tag",
			conf: TestConfigWithUppercase{
				ThisIsMissingAKoanfTag: "don't care",
			},
			assert: func(t *testing.T, err error, konf *koanf.Koanf) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(),
					"field ThisIsMissingAKoanfTag does not have lowercase key, use the `koanf` tag")
			},
		},
		{
			uc: "successful",
			conf: TestConfig{
				SomeString: "foo",
				SomeInt:    42,
				Nested1:    TestNestedConfig{SomeBool: true},
				Nested2:    []TestNestedConfig{{SomeString: "bar"}, {SomeString: "baz"}},
			},
			assert: func(t *testing.T, err error, konf *koanf.Koanf) {
				t.Helper()

				assert.NoError(t, err)
				konf.Print()

				assert.Equal(t, "foo", konf.Get("some_string"))
				assert.Equal(t, 42, konf.Get("someint"))
				assert.Equal(t, true, konf.Get("nested1.somebool"))
				assert.Empty(t, konf.Get("nested1.some_string"))
				assert.Len(t, konf.Get("nested_2"), 2)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			konf, err := koanfFromStruct(tc.conf)

			// THEN
			tc.assert(t, err, konf)
		})
	}
}
