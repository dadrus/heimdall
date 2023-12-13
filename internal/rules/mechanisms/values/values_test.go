// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package values

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
)

func TestValuesMerge(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		orig   Values
		tbm    Values
		assert func(t *testing.T, merged Values, orig Values)
	}{
		{
			uc: "original is nil, new is nil",
			assert: func(t *testing.T, merged Values, orig Values) {
				t.Helper()

				assert.Nil(t, merged)
			},
		},
		{
			uc: "original is nil, new is not",
			tbm: func() Values {
				bar, _ := template.New("bar")
				zab, _ := template.New("zab")

				return Values{"foo": bar, "baz": zab}
			}(),
			assert: func(t *testing.T, merged Values, orig Values) {
				t.Helper()

				require.Nil(t, orig)
				require.NotEmpty(t, merged)

				tpl := merged["foo"]
				require.NotNil(t, tpl)
				val, _ := tpl.Render(map[string]any{})
				assert.Equal(t, "bar", val)

				tpl = merged["baz"]
				require.NotNil(t, tpl)
				val, _ = tpl.Render(map[string]any{})
				assert.Equal(t, "zab", val)
			},
		},
		{
			uc: "original is not nil, new is nil",
			orig: func() Values {
				bar, _ := template.New("bar")
				zab, _ := template.New("zab")

				return Values{"foo": bar, "baz": zab}
			}(),
			assert: func(t *testing.T, merged Values, orig Values) {
				t.Helper()

				require.NotEmpty(t, merged)
				assert.Equal(t, orig, merged)
				assert.NotSame(t, orig, merged)
			},
		},
		{
			uc: "original is not nil, new is not nil",
			orig: func() Values {
				bar, _ := template.New("bar")

				return Values{"foo": bar}
			}(),
			tbm: func() Values {
				zab, _ := template.New("zab")

				return Values{"baz": zab}
			}(),
			assert: func(t *testing.T, merged Values, orig Values) {
				t.Helper()

				require.NotEmpty(t, merged)
				assert.NotEqual(t, orig, merged)
				assert.NotSame(t, orig, merged)
				assert.Len(t, merged, 2)

				tpl := merged["foo"]
				require.NotNil(t, tpl)
				val, _ := tpl.Render(map[string]any{})
				assert.Equal(t, "bar", val)

				tpl = merged["baz"]
				require.NotNil(t, tpl)
				val, _ = tpl.Render(map[string]any{})
				assert.Equal(t, "zab", val)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			res := tc.orig.Merge(tc.tbm)

			// THEN
			tc.assert(t, res, tc.orig)
		})
	}
}

func TestValuesRender(t *testing.T) {
	t.Parallel()

	badTpl, _ := template.New("{{ .Foo.Bar }}")
	fooTpl, _ := template.New("{{ .Foo }}")
	barTpl, _ := template.New("{{ .Bar }}")

	for _, tc := range []struct {
		uc     string
		values Values
		expErr bool
		expRes map[string]string
	}{
		{
			uc:     "render fails",
			values: Values{"foo": badTpl},
			expErr: true,
		},
		{
			uc:     "render succeeds",
			values: Values{"foo": fooTpl, "bar": barTpl},
			expErr: false,
			expRes: map[string]string{"foo": "foo", "bar": "bar"},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			res, err := tc.values.Render(map[string]any{"Foo": "foo", "Bar": "bar"})

			if tc.expErr {
				require.Error(t, err)
			} else {
				assert.Equal(t, tc.expRes, res)
			}
		})
	}
}
