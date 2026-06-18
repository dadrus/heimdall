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
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
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
		"fails if scopes provided on top level are not strings": {
			config: []byte(`
scopes:
  - foo
  - 2
`),
			assert: func(t *testing.T, err error, _ ScopesMatcher) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "invalid scope value '2'")
			},
		},
		"fails if matching strategy is unsupported": {
			config: []byte(`
scopes:
  values:
    - foo
  matching_strategy: unsupported
`),
			assert: func(t *testing.T, err error, _ ScopesMatcher) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, `unsupported strategy "unsupported"`)
			},
		},
		"fails if matching strategy is of wrong type": {
			config: []byte(`
scopes:
  values:
    - foo
  matching_strategy: 1
`),
			assert: func(t *testing.T, err error, _ ScopesMatcher) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, `invalid matching strategy type`)
			},
		},
		"fails if values are missing": {
			config: []byte(`
scopes:
  matching_strategy: exact
`),
			assert: func(t *testing.T, err error, _ ScopesMatcher) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "invalid structure for scopes matcher")
			},
		},
		"fails if scopes object has no values property": {
			config: []byte(`
scopes:
  foo: bar
`),
			assert: func(t *testing.T, err error, _ ScopesMatcher) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "invalid structure for scopes matcher")
			},
		},
		"does nothing if source is neither map nor slice": {
			config: []byte(`scopes: foo`),
			assert: func(t *testing.T, err error, matcher ScopesMatcher) {
				t.Helper()

				require.Error(t, err)
				assert.Nil(t, matcher)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

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

			err = dec.Decode(conf)

			tc.assert(t, err, typ.Matcher)
		})
	}
}

func TestDecodePoPStrategyHookFunc(t *testing.T) {
	t.Parallel()

	type Type struct {
		Strategy PoPStrategy `mapstructure:"proof_of_possession"`
	}

	for uc, tc := range map[string]struct {
		config []byte
		setup  func(
			t *testing.T,
			appCtx *app.ContextMock,
			resolver *secretsmocks.ResolverMock,
		)
		assert func(t *testing.T, err error, strategy PoPStrategy)
	}{
		"decodes dpop strategy without config": {
			config: []byte(`
proof_of_possession:
  type: dpop
`),
			setup: func(
				t *testing.T,
				appCtx *app.ContextMock,
				_ *secretsmocks.ResolverMock,
			) {
				t.Helper()

				appCtx.EXPECT().
					DecoderFactory().
					Return(encoding.NewDecoderFactory(nil))
			},
			assert: func(t *testing.T, err error, strategy PoPStrategy) {
				t.Helper()

				require.NoError(t, err)

				typed, ok := strategy.(*DPoPStrategy)
				require.True(t, ok)

				assert.Zero(t, typed.MaxAge)
				assert.Nil(t, typed.RequireNonce)
				assert.Nil(t, typed.ReplayAllowed)
				assert.Nil(t, typed.setInformer)
				assert.Empty(t, typed.currentKID)
			},
		},
		"decodes dpop strategy with config": {
			config: []byte(`
proof_of_possession:
  type: dpop
  config:
    max_age: 1m
    nonce_required: false
    replay_allowed: true
`),
			setup: func(
				t *testing.T,
				appCtx *app.ContextMock,
				_ *secretsmocks.ResolverMock,
			) {
				t.Helper()

				appCtx.EXPECT().
					DecoderFactory().
					Return(encoding.NewDecoderFactory(nil))
			},
			assert: func(t *testing.T, err error, strategy PoPStrategy) {
				t.Helper()

				require.NoError(t, err)

				typed, ok := strategy.(*DPoPStrategy)
				require.True(t, ok)

				assert.Equal(t, time.Minute, typed.MaxAge)

				require.NotNil(t, typed.RequireNonce)
				assert.False(t, *typed.RequireNonce)

				require.NotNil(t, typed.ReplayAllowed)
				assert.True(t, *typed.ReplayAllowed)

				assert.Nil(t, typed.setInformer)
				assert.Empty(t, typed.currentKID)
			},
		},
		"decodes dpop strategy with nonce manager": {
			config: []byte(`
proof_of_possession:
  type: dpop
  config:
    nonce_required: true
`),
			setup: func(
				t *testing.T,
				appCtx *app.ContextMock,
				resolver *secretsmocks.ResolverMock,
			) {
				t.Helper()

				appCtx.EXPECT().
					DecoderFactory().
					Return(encoding.NewDecoderFactory(nil))

				appCtx.EXPECT().
					Config().
					Return(&config.Configuration{
						MasterKey: &config.Secret{
							Source:   "master-keys",
							Selector: "key-1",
						},
					})

				appCtx.EXPECT().
					SecretResolver().
					Return(resolver)

				handle := secretsmocks.NewSecretSetHandleMock(t)
				handle.EXPECT().
					OnUpdate(mock.Anything).
					Return()

				resolver.EXPECT().
					SecretSet(secrets.Reference{Source: "master-keys"}).
					Return(handle, nil)
			},
			assert: func(t *testing.T, err error, strategy PoPStrategy) {
				t.Helper()

				require.NoError(t, err)

				typed, ok := strategy.(*DPoPStrategy)
				require.True(t, ok)

				require.NotNil(t, typed.RequireNonce)
				assert.True(t, *typed.RequireNonce)

				require.NotNil(t, typed.setInformer)
				assert.Equal(t, "key-1", typed.currentKID)
			},
		},
		"decodes mtls strategy": {
			config: []byte(`
proof_of_possession:
  type: mtls
`),
			assert: func(t *testing.T, err error, strategy PoPStrategy) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &mtlsPoPStrategy{}, strategy)
			},
		},
		"fails if proof of possession type is unsupported": {
			config: []byte(`
proof_of_possession:
  type: unsupported
`),
			assert: func(t *testing.T, err error, _ PoPStrategy) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, `unsupported proof_of_possession type "unsupported"`)
			},
		},
		"fails if dpop config has unexpected type": {
			config: []byte(`
proof_of_possession:
  type: dpop
  config:
    - foo
`),
			assert: func(t *testing.T, err error, _ PoPStrategy) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "unexpected configuration type")
			},
		},
		"fails if dpop config contains unsupported property": {
			config: []byte(`
proof_of_possession:
  type: dpop
  config:
    unknown: value
`),
			setup: func(
				t *testing.T,
				appCtx *app.ContextMock,
				_ *secretsmocks.ResolverMock,
			) {
				t.Helper()

				appCtx.EXPECT().
					DecoderFactory().
					Return(encoding.NewDecoderFactory(nil))
			},
			assert: func(t *testing.T, err error, _ PoPStrategy) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding DPoP config")
			},
		},
		"does nothing if source is not a map": {
			config: []byte(`proof_of_possession: dpop`),
			assert: func(t *testing.T, err error, _ PoPStrategy) {
				t.Helper()

				require.Error(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var typ Type

			appCtx := app.NewContextMock(t)
			resolver := secretsmocks.NewResolverMock(t)

			if tc.setup != nil {
				tc.setup(t, appCtx, resolver)
			}

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					DecodePoPStrategyHookFunc(appCtx),
				),
				Result: &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			err = dec.Decode(conf)

			tc.assert(t, err, typ.Strategy)
		})
	}
}

func TestAsStringMap(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		data   any
		assert func(t *testing.T, result map[string]any, err error)
	}{
		"returns empty map for nil": {
			assert: func(t *testing.T, result map[string]any, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, result)
			},
		},
		"returns string map unchanged": {
			data: map[string]any{
				"foo": "bar",
			},
			assert: func(t *testing.T, result map[string]any, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, map[string]any{"foo": "bar"}, result)
			},
		},
		"converts any map with string keys": {
			data: map[any]any{
				"foo": "bar",
			},
			assert: func(t *testing.T, result map[string]any, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, map[string]any{"foo": "bar"}, result)
			},
		},
		"fails for any map with non-string key": {
			data: map[any]any{
				1: "bar",
			},
			assert: func(t *testing.T, _ map[string]any, err error) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "configuration contains non-string key")
			},
		},
		"fails for unexpected type": {
			data: []any{"foo"},
			assert: func(t *testing.T, _ map[string]any, err error) {
				t.Helper()

				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "unexpected configuration type")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			result, err := asStringMap(tc.data)

			tc.assert(t, result, err)
		})
	}
}
