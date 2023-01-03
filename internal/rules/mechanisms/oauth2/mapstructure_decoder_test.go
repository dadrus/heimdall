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

package oauth2

import (
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestDecodeScopesMatcherHookFunc(t *testing.T) {
	t.Parallel()

	type Type struct {
		Matcher ScopesMatcher `mapstructure:"scopes"`
	}

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, matcher ScopesMatcher)
	}{
		{
			uc: "structure with scopes under value and wildcard strategy",
			config: []byte(`
scopes:
  values:
    - foo
    - bar
  matching_strategy: wildcard
`),
			assert: func(t *testing.T, err error, matcher ScopesMatcher) {
				t.Helper()

				require.NoError(t, err)

				assert.IsType(t, WildcardScopeStrategyMatcher{}, matcher)
				assert.ElementsMatch(t, matcher, []string{"foo", "bar"})
			},
		},
		{
			uc: "structure with scopes under value and exact strategy",
			config: []byte(`
scopes:
  values:
    - foo
    - bar
  matching_strategy: exact
`),
			assert: func(t *testing.T, err error, matcher ScopesMatcher) {
				t.Helper()

				require.NoError(t, err)

				assert.IsType(t, ExactScopeStrategyMatcher{}, matcher)
				assert.ElementsMatch(t, matcher, []string{"foo", "bar"})
			},
		},
		{
			uc: "structure with scopes under value and hierarchic strategy",
			config: []byte(`
scopes:
  values:
    - foo
    - bar
  matching_strategy: hierarchic
`),
			assert: func(t *testing.T, err error, matcher ScopesMatcher) {
				t.Helper()

				require.NoError(t, err)

				assert.IsType(t, HierarchicScopeStrategyMatcher{}, matcher)
				assert.ElementsMatch(t, matcher, []string{"foo", "bar"})
			},
		},
		{
			uc: "only scopes provided under values property",
			config: []byte(`
scopes:
  values:
    - foo
    - bar
`),
			assert: func(t *testing.T, err error, matcher ScopesMatcher) {
				t.Helper()

				require.NoError(t, err)

				assert.IsType(t, ExactScopeStrategyMatcher{}, matcher)
				assert.ElementsMatch(t, matcher, []string{"foo", "bar"})
			},
		},
		{
			uc: "only scopes provided on top level",
			config: []byte(`
scopes:
  - foo
  - bar
`),
			assert: func(t *testing.T, err error, matcher ScopesMatcher) {
				t.Helper()

				require.NoError(t, err)

				assert.IsType(t, ExactScopeStrategyMatcher{}, matcher)
				assert.ElementsMatch(t, matcher, []string{"foo", "bar"})
			},
		},
		{
			uc: "no scopes provided, but matching strategy",
			config: []byte(`
scopes:
  matching_strategy: exact
`),
			assert: func(t *testing.T, err error, matcher ScopesMatcher) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc: "malformed configuration",
			config: []byte(`
scopes:
  foo: bar
`),
			assert: func(t *testing.T, err error, matcher ScopesMatcher) {
				t.Helper()

				assert.Error(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					DecodeScopesMatcherHookFunc(),
				),
				Result: &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			tc.assert(t, err, typ.Matcher)
		})
	}
}
