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

package finalizers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
	heimdallmocks "github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewJWTFinalizer(t *testing.T) {
	t.Parallel()

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	secret := secrettypes.NewAsymmetricKeySecret("bar", "baz", privKey, nil)

	for uc, tc := range map[string]struct {
		config []byte
		setup  func(t *testing.T, resolver *secretsmocks.ResolverMock)
		assert func(t *testing.T, err error, fin *jwtFinalizer)
	}{
		"missing signer": {
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'signer' is a required field")
			},
		},
		"missing secret source": {
			config: []byte(`
signer:
  secret:
    selector: bar
`),
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'signer'.'secret'.'source' is a required field")
			},
		},
		"signer creation fails": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			setup: func(t *testing.T, resolver *secretsmocks.ResolverMock) {
				t.Helper()

				resolver.EXPECT().
					Secret(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed creating secret informer")
			},
		},
		"minimal valid config": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			setup: func(t *testing.T, resolver *secretsmocks.ResolverMock) {
				t.Helper()

				shm := secretsmocks.NewSecretHandleMock(t)
				shm.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))

				resolver.EXPECT().
					Secret(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(shm, nil)
			},
			assert: func(t *testing.T, err error, fin *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, fin)
				assert.Equal(t, "minimal valid config", fin.ID())
				assert.Equal(t, types.KindFinalizer, fin.Kind())
				assert.Equal(t, fin.ID(), fin.Name())
				assert.Equal(t, defaultJWTTTL, fin.ttl)
				assert.Equal(t, "Authorization", fin.headerName)
				assert.Equal(t, "Bearer", fin.headerScheme)
				assert.NotNil(t, fin.signer)
				assert.Nil(t, fin.claims)
				assert.Empty(t, fin.v)
			},
		},
		"full valid config": {
			config: []byte(`
ttl: 10s
signer:
  name: foo
  secret:
    source: foo
    selector: bar
claims: '{ "sub": {{ quote .Subject.ID }} }'
header:
  name: X-Test
  scheme: Test
values:
  foo: '{{ .Subject.ID }}'
`),
			setup: func(t *testing.T, resolver *secretsmocks.ResolverMock) {
				t.Helper()

				shm := secretsmocks.NewSecretHandleMock(t)
				shm.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), secret)
						require.NoError(t, err)

						return true
					}))

				resolver.EXPECT().
					Secret(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(shm, nil)
			},
			assert: func(t *testing.T, err error, fin *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, fin)
				assert.Equal(t, "full valid config", fin.ID())
				assert.Equal(t, types.KindFinalizer, fin.Kind())
				assert.Equal(t, fin.ID(), fin.Name())
				assert.Equal(t, 10*time.Second, fin.ttl)
				assert.Equal(t, "X-Test", fin.headerName)
				assert.Equal(t, "Test", fin.headerScheme)
				assert.NotNil(t, fin.claims)
				assert.Len(t, fin.v, 1)
				assert.NotNil(t, fin.signer)
				assert.Equal(t, "foo", fin.signer.iss)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			setup := x.IfThenElse(
				tc.setup != nil,
				tc.setup,
				func(t *testing.T, _ *secretsmocks.ResolverMock) { t.Helper() },
			)

			resolver := secretsmocks.NewResolverMock(t)
			setup(t, resolver)

			ko := keyregistrymocks.NewRegistryMock(t)
			ko.EXPECT().Notify(mock.Anything).Maybe()

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Return(log.Logger)
			appCtx.EXPECT().SecretResolver().Maybe().Return(resolver)
			appCtx.EXPECT().KeyRegistry().Maybe().Return(ko)

			mech, err := newJWTFinalizer(appCtx, uc, conf)

			fin, _ := mech.(*jwtFinalizer)
			tc.assert(t, err, fin)
		})
	}
}

func TestJWTFinalizerCreateStep(t *testing.T) {
	t.Parallel()

	const expectedTTL = 5 * time.Second

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	secret := secrettypes.NewAsymmetricKeySecret("bar", "baz", privKey, nil)

	for uc, tc := range map[string]struct {
		config  []byte
		stepDef types.StepDefinition
		assert  func(t *testing.T, err error, prototype, configured *jwtFinalizer)
	}{
		"no new configuration and no step ID": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			assert: func(t *testing.T, err error, prototype, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"no new configuration but with step ID": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			stepDef: types.StepDefinition{ID: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, "no new configuration but with step ID", prototype.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, types.KindFinalizer, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
				assert.Equal(t, prototype.claims, configured.claims)
				assert.Equal(t, "Authorization", configured.headerName)
				assert.Equal(t, "Bearer", configured.headerScheme)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, defaultJWTTTL, configured.ttl)
				assert.Equal(t, prototype.signer, configured.signer)
				assert.Equal(t, prototype.v, configured.v)
			},
		},
		"configuration with ttl and step ID": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			stepDef: types.StepDefinition{
				ID:     "bar",
				Config: config.MechanismConfig{"ttl": "5s"},
			},
			assert: func(t *testing.T, err error, prototype, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.claims, configured.claims)
				assert.Equal(t, "Authorization", configured.headerName)
				assert.Equal(t, "Bearer", configured.headerScheme)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, expectedTTL, configured.ttl)
				assert.Equal(t, "configuration with ttl and step ID", prototype.ID())
				assert.Equal(t, "bar", configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, types.KindFinalizer, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
				assert.Equal(t, prototype.signer, configured.signer)
				assert.Equal(t, prototype.v, configured.v)
			},
		},
		"configuration with too short ttl": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{"ttl": "5ms"},
			},
			assert: func(t *testing.T, err error, _, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'ttl' must be greater than 1s")
			},
		},
		"configuration with claims only provided": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{"claims": `{"sub": {{ quote .Subject.ID }} }`},
			},
			assert: func(t *testing.T, err error, prototype, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, "Authorization", configured.headerName)
				assert.Equal(t, "Bearer", configured.headerScheme)
				assert.NotEqual(t, prototype.claims, configured.claims)
				require.NotNil(t, configured.claims)

				val, err := configured.claims.Render(map[string]any{
					"Subject": pipeline.Subject{"default": &pipeline.Principal{ID: "bar"}},
				})
				require.NoError(t, err)
				assert.JSONEq(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "configuration with claims only provided", configured.ID())
				assert.Equal(t, types.KindFinalizer, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
				assert.Equal(t, prototype.signer, configured.signer)
				assert.Equal(t, prototype.v, configured.v)
			},
		},
		"configuration with claims and values": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{
					"claims": `{"foo": {{ .Values.foo }} }`,
					"values": map[string]any{"foo": "{{ quote .Subject.ID }}"},
				},
			},
			assert: func(t *testing.T, err error, prototype, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "Authorization", configured.headerName)
				assert.Equal(t, "Bearer", configured.headerScheme)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, defaultJWTTTL, configured.ttl)
				assert.Nil(t, prototype.claims)
				assert.NotEqual(t, prototype.claims, configured.claims)
				require.NotNil(t, configured.claims)
				assert.Equal(t, "configuration with claims and values", configured.ID())
				assert.Equal(t, types.KindFinalizer, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
				assert.NotEmpty(t, configured.v)
				assert.Equal(t, prototype.signer, configured.signer)

				vals, err := configured.v.Render(map[string]any{
					"Subject": pipeline.Subject{"default": &pipeline.Principal{ID: "bar"}},
				})
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"foo": `"bar"`}, vals)
			},
		},
		"configuration with both ttl and claims provided": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{
					"claims": `{"sub": {{ quote .Subject.ID }} }`,
					"ttl":    "5s",
				},
			},
			assert: func(t *testing.T, err error, prototype, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "Authorization", configured.headerName)
				assert.Equal(t, "Bearer", configured.headerScheme)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, expectedTTL, configured.ttl)
				assert.NotEqual(t, prototype.claims, configured.claims)
				require.NotNil(t, configured.claims)

				val, err := configured.claims.Render(map[string]any{
					"Subject": pipeline.Subject{"default": &pipeline.Principal{ID: "bar"}},
				})
				require.NoError(t, err)
				assert.JSONEq(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "configuration with both ttl and claims provided", configured.ID())
				assert.Equal(t, types.KindFinalizer, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
				assert.Equal(t, prototype.signer, configured.signer)
			},
		},
		"configuration with values": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
claims: '{ "foo": {{ quote .Values.foo }} }'
values:
  foo: bar
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{
					"values": map[string]any{"foo": "{{ .Subject.ID }}"},
				},
			},
			assert: func(t *testing.T, err error, prototype, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "Authorization", configured.headerName)
				assert.Equal(t, "Bearer", configured.headerScheme)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, defaultJWTTTL, configured.ttl)
				assert.Equal(t, prototype.claims, configured.claims)
				require.NotNil(t, configured.claims)
				assert.Equal(t, "configuration with values", configured.ID())
				assert.Equal(t, types.KindFinalizer, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
				assert.NotEmpty(t, configured.v)
				assert.Equal(t, prototype.signer, configured.signer)

				vals, err := configured.v.Render(map[string]any{
					"Subject": pipeline.Subject{"default": &pipeline.Principal{ID: "bar"}},
				})
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"foo": "bar"}, vals)
			},
		},
		"with unknown entries in configuration": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"foo": "bar"}},
			assert: func(t *testing.T, err error, prototype, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"signer reconfiguration is not allowed": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{
				"signer": map[string]any{
					"secret": map[string]any{"source": "foo", "selector": "baz"},
				},
			}},
			assert: func(t *testing.T, err error, _, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'signer' is not allowed")
			},
		},
		"header reconfiguration is not allowed": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{
				"header": map[string]any{"name": "X-Test", "scheme": "Test"},
			}},
			assert: func(t *testing.T, err error, _, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "'header' is not allowed")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			protoConf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			shm := secretsmocks.NewSecretHandleMock(t)
			shm.EXPECT().
				OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
					err := cb(t.Context(), secret)
					require.NoError(t, err)

					return true
				}))

			resolver := secretsmocks.NewResolverMock(t)
			resolver.EXPECT().
				Secret(secrets.Reference{Source: "foo", Selector: "bar"}).
				Return(shm, nil)

			ko := keyregistrymocks.NewRegistryMock(t)
			ko.EXPECT().Notify(mock.Anything).Maybe()

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().KeyRegistry().Return(ko)
			appCtx.EXPECT().SecretResolver().Return(resolver)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Return(log.Logger)

			mech, err := newJWTFinalizer(appCtx, uc, protoConf)
			require.NoError(t, err)

			configured, ok := mech.(*jwtFinalizer)
			require.True(t, ok)

			stepResolver := secretsmocks.NewResolverMock(t)

			step, err := mech.CreateStep(stepResolver, tc.stepDef)

			fin, ok := step.(*jwtFinalizer)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, configured, fin)
		})
	}
}

func TestJWTFinalizerExecute(t *testing.T) {
	t.Parallel()

	const configuredTTL = 1 * time.Minute

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	secret := secrettypes.NewAsymmetricKeySecret("bar", "baz", privKey, nil)

	for uc, tc := range map[string]struct {
		config         []byte
		subject        pipeline.Subject
		signingSecret  secrets.Secret
		configureMocks func(t *testing.T,
			fin *jwtFinalizer,
			ctx *heimdallmocks.ContextMock,
			cch *mocks.CacheMock,
			ssh *secretsmocks.SecretHandleMock,
			sub pipeline.Subject)
		assert func(t *testing.T, err error)
	}{
		"with 'nil' identity": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "'nil' identity")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "with 'nil' identity", identifier.ID())
			},
		},
		"with used prefilled cache": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "foo",
					Attributes: map[string]any{"baz": "bar"},
				},
			},
			configureMocks: func(t *testing.T, fin *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, _ *secretsmocks.SecretHandleMock, sub pipeline.Subject,
			) {
				t.Helper()

				outputs := map[string]any{"foo": "bar"}
				ctx.EXPECT().Outputs().Return(outputs)
				ctx.EXPECT().AddHeaderForUpstream("Authorization", "Bearer TestToken")

				cacheKey := fin.calculateCacheKey(ctx, sub)
				cch.EXPECT().Get(mock.Anything, cacheKey).Return([]byte("TestToken"), nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with no cache hit and without custom claims": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
ttl: 1m
`),
			signingSecret: secret,
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "foo",
					Attributes: map[string]any{"baz": "bar"},
				},
			},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, _ *secretsmocks.SecretHandleMock, _ pipeline.Subject,
			) {
				t.Helper()

				ctx.EXPECT().Outputs().Return(map[string]any{})
				ctx.EXPECT().AddHeaderForUpstream("Authorization",
					mock.MatchedBy(func(val string) bool { return strings.HasPrefix(val, "Bearer ") }))
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, configuredTTL-defaultCacheLeeway).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with no cache hit and ttl too short for caching": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
ttl: 2s
`),
			signingSecret: secret,
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "foo",
					Attributes: map[string]any{"baz": "bar"},
				},
			},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, _ *secretsmocks.SecretHandleMock, _ pipeline.Subject,
			) {
				t.Helper()

				ctx.EXPECT().Outputs().Return(map[string]any{})
				ctx.EXPECT().AddHeaderForUpstream("Authorization",
					mock.MatchedBy(func(val string) bool { return strings.HasPrefix(val, "Bearer ") }))
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with no cache hit, with custom claims and custom header": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
header:
  name: X-Token
  scheme: Bar
claims: '{
  {{ $val := .Subject.Attributes.baz }}
  "sub_id": {{ quote .Subject.ID }}, 
  {{ quote $val }}: "baz",
  "foo": {{ .Outputs.foo | quote }}
}'`),
			signingSecret: secret,
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "foo",
					Attributes: map[string]any{"baz": "bar"},
				},
			},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, _ *secretsmocks.SecretHandleMock, _ pipeline.Subject,
			) {
				t.Helper()

				ctx.EXPECT().Outputs().Return(map[string]any{"foo": "bar"})
				ctx.EXPECT().AddHeaderForUpstream("X-Token",
					mock.MatchedBy(func(val string) bool { return strings.HasPrefix(val, "Bar ") }))

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, defaultJWTTTL-defaultCacheLeeway).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with no cache hit, with custom claims and values": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
claims: '{{- dict "foo" .Values.foo "bar" .Values.bar | toJson -}}'
values:
  foo: '{{ .Subject.ID | quote }}'
  bar: '{{ .Outputs.bar | quote }}'
`),
			signingSecret: secret,
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "foo",
					Attributes: map[string]any{"baz": "bar"},
				},
			},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, _ *secretsmocks.SecretHandleMock, _ pipeline.Subject,
			) {
				t.Helper()

				ctx.EXPECT().Outputs().Return(map[string]any{"bar": "baz"})
				ctx.EXPECT().AddHeaderForUpstream("Authorization",
					mock.MatchedBy(func(val string) bool { return strings.HasPrefix(val, "Bearer ") }))

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, defaultJWTTTL-defaultCacheLeeway).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with custom claims template, which does not result in a JSON object": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
claims: "foo: bar"
`),
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "foo",
					Attributes: map[string]any{"baz": "bar"},
				},
			},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, _ *secretsmocks.SecretHandleMock, _ pipeline.Subject,
			) {
				t.Helper()

				ctx.EXPECT().Outputs().Return(map[string]any{})
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "failed to unmarshal claims")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "with custom claims template, which does not result in a JSON object", identifier.ID())
			},
		},
		"with custom claims template, which fails during rendering": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
claims: "{{ len .foobar }}"
`),
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "foo",
					Attributes: map[string]any{"baz": "bar"},
				},
			},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, _ *secretsmocks.SecretHandleMock, _ pipeline.Subject,
			) {
				t.Helper()

				ctx.EXPECT().Outputs().Return(map[string]any{})
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "failed to render claims")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "with custom claims template, which fails during rendering", identifier.ID())
			},
		},
		"with values template, which fails during rendering": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
claims: "{{ quote .Values.foo }}"
values:
  foo: '{{ len .fooo }}'
`),
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID:         "foo",
					Attributes: map[string]any{"baz": "bar"},
				},
			},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, _ *secretsmocks.SecretHandleMock, _ pipeline.Subject,
			) {
				t.Helper()

				ctx.EXPECT().Outputs().Return(map[string]any{})
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "failed to render values")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "with values template, which fails during rendering", identifier.ID())
			},
		},
		"fails signing": {
			config: []byte(`
signer:
  secret:
    source: foo
    selector: bar
`),
			subject: pipeline.Subject{
				"default": &pipeline.Principal{
					ID: "foo",
				},
			},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, _ *secretsmocks.SecretHandleMock, _ pipeline.Subject,
			) {
				t.Helper()

				ctx.EXPECT().Outputs().Return(map[string]any{})
				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "jwt signing material is not available")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "fails signing", identifier.ID())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *jwtFinalizer, _ *heimdallmocks.ContextMock,
					_ *mocks.CacheMock, _ *secretsmocks.SecretHandleMock, _ pipeline.Subject,
				) {
					t.Helper()
				})

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			cch := mocks.NewCacheMock(t)
			mctx := heimdallmocks.NewContextMock(t)

			shm := secretsmocks.NewSecretHandleMock(t)
			if tc.signingSecret != nil {
				shm.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(t.Context(), tc.signingSecret)
						require.NoError(t, err)

						return true
					}))
			} else {
				shm.EXPECT().OnUpdate(mock.Anything)
			}

			resolver := secretsmocks.NewResolverMock(t)
			resolver.EXPECT().
				Secret(secrets.Reference{Source: "foo", Selector: "bar"}).
				Return(shm, nil)

			ko := keyregistrymocks.NewRegistryMock(t)
			ko.EXPECT().Notify(mock.Anything).Maybe()

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().KeyRegistry().Return(ko)
			appCtx.EXPECT().SecretResolver().Return(resolver)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Return(log.Logger)

			mctx.EXPECT().Context().Return(cache.WithContext(t.Context(), cch))

			mech, err := newJWTFinalizer(appCtx, uc, conf)
			require.NoError(t, err)

			configured, ok := mech.(*jwtFinalizer)
			require.True(t, ok)

			step, err := mech.CreateStep(secretsmocks.NewResolverMock(t), types.StepDefinition{})
			require.NoError(t, err)

			configureMocks(t, configured, mctx, cch, shm, tc.subject)

			err = step.Execute(mctx, tc.subject)

			tc.assert(t, err)
		})
	}
}

func TestJWTFinalizerAccept(t *testing.T) {
	t.Parallel()

	mech := &jwtFinalizer{}

	mech.Accept(nil)
}
