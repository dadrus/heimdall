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

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestDecodeScopesMatcherHookFunc(t *testing.T) {
	t.Parallel()

	type Type struct {
		Matcher ScopesMatcher `mapstructure:"scopes"`
	}

	for uc, tc := range map[string]struct {
		config []byte
		assert func(t *testing.T, err error, matcher ScopesMatcher)
	}{
		"structure with scopes under value and wildcard strategy": {
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
		"structure with scopes under value and exact strategy": {
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
		"structure with scopes under value and hierarchic strategy": {
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
		"only scopes provided under values property": {
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
		"only scopes provided on top level": {
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
		"no scopes provided, but matching strategy": {
			config: []byte(`
scopes:
  matching_strategy: exact
`),
			assert: func(t *testing.T, err error, _ ScopesMatcher) {
				t.Helper()

				require.Error(t, err)
			},
		},
		"malformed configuration": {
			config: []byte(`
scopes:
  foo: bar
`),
			assert: func(t *testing.T, err error, _ ScopesMatcher) {
				t.Helper()

				require.Error(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
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
