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
			uc:  "original is nil, new is not",
			tbm: Values{"foo": "bar", "baz": "zab"},
			assert: func(t *testing.T, merged Values, orig Values) {
				t.Helper()

				require.Nil(t, orig)
				require.NotEmpty(t, merged)
				assert.Equal(t, "bar", merged["foo"])
				assert.Equal(t, "zab", merged["baz"])
			},
		},
		{
			uc:   "original is not nil, new is nil",
			orig: Values{"foo": "bar", "baz": "zab"},
			assert: func(t *testing.T, merged Values, orig Values) {
				t.Helper()

				require.NotEmpty(t, merged)
				assert.Equal(t, orig, merged)
				assert.NotSame(t, orig, merged)
			},
		},
		{
			uc:   "original is not nil, new is not nil",
			orig: Values{"foo": "bar"},
			tbm:  Values{"baz": "zab"},
			assert: func(t *testing.T, merged Values, orig Values) {
				t.Helper()

				require.NotEmpty(t, merged)
				assert.NotEqual(t, orig, merged)
				assert.NotSame(t, orig, merged)
				assert.Len(t, merged, 2)
				assert.Equal(t, "bar", merged["foo"])
				assert.Equal(t, "zab", merged["baz"])
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
