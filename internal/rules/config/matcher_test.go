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

func TestMatcherUnmarshalJSON(t *testing.T) {
	t.Parallel()

	type Typ struct {
		Matcher Matcher `json:"match"`
	}

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, matcher *Matcher)
	}{
		{
			uc:     "specified as string",
			config: []byte(`{ "match": "foo.bar" }`),
			assert: func(t *testing.T, err error, matcher *Matcher) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo.bar", matcher.URL)
				assert.Equal(t, "glob", matcher.Strategy)
			},
		},
		{
			uc: "specified as structured type with invalid json structure",
			config: []byte(`{
"match": {
  strategy: foo
}
}`),
			assert: func(t *testing.T, err error, _ *Matcher) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid character")
			},
		},
		{
			uc: "specified as structured type without url",
			config: []byte(`{
"match": {
  "strategy": "foo"
}
}`),
			assert: func(t *testing.T, err error, _ *Matcher) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), ErrURLMissing.Error())
			},
		},
		{
			uc: "specified as structured type without strategy specified",
			config: []byte(`{
"match": {
  "url": "foo.bar"
}
}`),
			assert: func(t *testing.T, err error, matcher *Matcher) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo.bar", matcher.URL)
				assert.Equal(t, "glob", matcher.Strategy)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			var typ Typ

			// WHEN
			err := json.Unmarshal(tc.config, &typ)

			// THEN
			tc.assert(t, err, &typ.Matcher)
		})
	}
}
