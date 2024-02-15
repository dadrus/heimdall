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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestMatcherDecodeHookFunc(t *testing.T) {
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
			config: []byte(`match: foo.bar`),
			assert: func(t *testing.T, err error, matcher *Matcher) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo.bar", matcher.URL)
				assert.Equal(t, "glob", matcher.Strategy)
			},
		},
		{
			uc: "specified as structured type without url",
			config: []byte(`
match: 
  strategy: foo
`),
			assert: func(t *testing.T, err error, _ *Matcher) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), ErrURLMissing.Error())
			},
		},
		{
			uc: "specified as structured type with bad url type",
			config: []byte(`
match: 
  url: 1
`),
			assert: func(t *testing.T, err error, _ *Matcher) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), ErrURLType.Error())
			},
		},
		{
			uc: "specified as structured type with bad strategy type",
			config: []byte(`
match: 
  url: foo.bar
  strategy: true
`),
			assert: func(t *testing.T, err error, _ *Matcher) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), ErrStrategyType.Error())
			},
		},
		{
			uc: "specified as structured type with unsupported strategy",
			config: []byte(`
match: 
  url: foo.bar
  strategy: foo
`),
			assert: func(t *testing.T, err error, _ *Matcher) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), ErrUnsupportedStrategy.Error())
			},
		},
		{
			uc: "specified as structured type without strategy specified",
			config: []byte(`
match: 
  url: foo.bar
`),
			assert: func(t *testing.T, err error, matcher *Matcher) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo.bar", matcher.URL)
				assert.Equal(t, "glob", matcher.Strategy)
			},
		},
		{
			uc: "specified as structured type with glob strategy specified",
			config: []byte(`
match: 
  url: foo.bar
  strategy: glob
`),
			assert: func(t *testing.T, err error, matcher *Matcher) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo.bar", matcher.URL)
				assert.Equal(t, "glob", matcher.Strategy)
			},
		},
		{
			uc: "specified as structured type with regex strategy specified",
			config: []byte(`
match: 
  url: foo.bar
  strategy: regex
`),
			assert: func(t *testing.T, err error, matcher *Matcher) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo.bar", matcher.URL)
				assert.Equal(t, "regex", matcher.Strategy)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			raw, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			var typ Typ

			// WHEN
			err = DecodeConfig(raw, &typ)

			// THEN
			tc.assert(t, err, &typ.Matcher)
		})
	}
}
