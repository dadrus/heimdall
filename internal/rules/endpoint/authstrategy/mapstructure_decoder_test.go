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

package authstrategy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestDecodeAuthenticationStrategyHookFuncForBasicAuthStrategy(t *testing.T) {
	t.Parallel()

	type Type struct {
		AuthStrategy endpoint.AuthenticationStrategy `mapstructure:"auth"`
	}

	// du to a bug in the linter
	for uc, tc := range map[string]struct {
		config []byte
		setup  func(t *testing.T, sm *secretsmocks.ManagerMock)
		assert func(t *testing.T, err error, as endpoint.AuthenticationStrategy)
	}{
		"all required properties configured": {
			config: []byte(`
auth:
  type: basic_auth
  config:
    credentials:
      source: foo
      selector: bar
`),
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).Return(func() {}, nil)
				sm.EXPECT().ResolveCredentials(mock.Anything, mock.Anything).
					Return(
						secrettypes.NewCredentials("foo", "bar", map[string]any{
							"user_id":  "baz",
							"password": "zab",
						}),
						nil)
			},
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &BasicAuth{}, as)
				bas := as.(*BasicAuth) // nolint: forcetypeassert
				require.NotNil(t, bas.resolver)
			},
		},
		"with unsupported properties": {
			config: []byte(`
auth:
  type: basic_auth
  config:
    credentials:
      source: foo
      selector: bar
    foo: bar
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "invalid keys: foo")
			},
		},
		"without source property": {
			config: []byte(`
auth:
  type: basic_auth
  config:
    credentials:
      selector: bar
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'source' is a required field")
			},
		},
		"without config property": {
			config: []byte(`
auth:
  type: basic_auth
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'config' property to be set")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			validator, err := validation.NewValidator()
			require.NoError(t, err)

			setup := x.IfThenElse(tc.setup != nil, tc.setup, func(t *testing.T, _ *secretsmocks.ManagerMock) { t.Helper() })

			sm := secretsmocks.NewManagerMock(t)
			setup(t, sm)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Maybe().Return(log.Logger)
			appCtx.EXPECT().SecretsManager().Maybe().Return(sm)

			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					DecodeAuthenticationStrategyHookFunc(appCtx),
				),
				Result: &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			tc.assert(t, err, typ.AuthStrategy)
		})
	}
}

func TestDecodeAuthenticationStrategyHookFuncForAPIKeyStrategy(t *testing.T) {
	t.Parallel()

	type Type struct {
		AuthStrategy endpoint.AuthenticationStrategy `mapstructure:"auth"`
	}

	// du to a bug in the linter
	for uc, tc := range map[string]struct {
		config []byte
		setup  func(t *testing.T, sm *secretsmocks.ManagerMock)
		assert func(t *testing.T, err error, as endpoint.AuthenticationStrategy)
	}{
		"all required properties, with in=header": {
			config: []byte(`
auth:
  type: api_key
  config:
    name: foo
    secret:
      source: foo
      selector: bar
    in: header
`),
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).
					Return(func() {}, nil)
				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).
					Return(secrettypes.NewStringSecret("foo", "bar", "baz"), nil)
			},
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &APIKey{}, as)
				aks := as.(*APIKey) // nolint: forcetypeassert
				assert.Equal(t, "foo", aks.Name)
				assert.NotNil(t, aks.resolver)
				assert.Equal(t, "header", aks.In)
			},
		},
		"with unsupported properties": {
			config: []byte(`
auth:
  type: api_key
  config:
    name: foo
    secret:
      source: foo
      selector: bar
    in: header
    foo: bar
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "invalid keys: foo")
			},
		},
		"all required properties, with in=cookie": {
			config: []byte(`
auth:
  type: api_key
  config:
    name: foo
    secret:
      source: foo
      selector: bar
    in: cookie
`),
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).
					Return(func() {}, nil)
				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).
					Return(secrettypes.NewStringSecret("foo", "bar", "baz"), nil)
			},
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &APIKey{}, as)
				aks := as.(*APIKey) // nolint: forcetypeassert
				assert.Equal(t, "foo", aks.Name)
				assert.NotNil(t, aks.resolver)
				assert.Equal(t, "cookie", aks.In)
			},
		},
		"all required properties, with in=query": {
			config: []byte(`
auth:
  type: api_key
  config:
    name: foo
    secret:
      source: foo
      selector: bar
    in: query
`),
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).
					Return(func() {}, nil)
				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).
					Return(secrettypes.NewStringSecret("foo", "bar", "baz"), nil)
			},
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &APIKey{}, as)
				aks := as.(*APIKey) // nolint: forcetypeassert
				assert.Equal(t, "foo", aks.Name)
				assert.Equal(t, "query", aks.In)
				assert.NotNil(t, aks.resolver)
			},
		},
		"all required properties, with in=foobar": {
			config: []byte(`
auth:
  type: api_key
  config:
    name: foo
    secret:
      source: foo
      selector: bar
    in: foobar
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'in' must be one of [cookie header query]")
			},
		},
		"without in property": {
			config: []byte(`
auth:
  type: api_key
  config:
    name: foo
    secret:
      source: foo
      selector: bar
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'in' is a required field")
			},
		},
		"without name property": {
			config: []byte(`
auth:
  type: api_key
  config:
    secret:
      source: foo
      selector: bar
    in: header
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'name' is a required field")
			},
		},
		"without secret property": {
			config: []byte(`
auth:
  type: api_key
  config:
    name: foo
    in: header
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'secret' is a required field")
			},
		},
		"without config property": {
			config: []byte(`
auth:
  type: api_key
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'config' property to be set")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			validator, err := validation.NewValidator()
			require.NoError(t, err)

			setup := x.IfThenElse(tc.setup != nil, tc.setup, func(t *testing.T, _ *secretsmocks.ManagerMock) { t.Helper() })

			sm := secretsmocks.NewManagerMock(t)
			setup(t, sm)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Maybe().Return(log.Logger)
			appCtx.EXPECT().SecretsManager().Maybe().Return(sm)

			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					DecodeAuthenticationStrategyHookFunc(appCtx),
				),
				Result: &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			tc.assert(t, err, typ.AuthStrategy)
		})
	}
}

func TestDecodeAuthenticationStrategyHookFuncForClientCredentialsStrategy(t *testing.T) {
	t.Parallel()

	type Type struct {
		AuthStrategy endpoint.AuthenticationStrategy `mapstructure:"auth"`
	}

	for uc, tc := range map[string]struct {
		enforceTLS bool
		config     []byte
		setup      func(t *testing.T, sm *secretsmocks.ManagerMock)
		assert     func(t *testing.T, err error, as endpoint.AuthenticationStrategy)
	}{
		"minimal possible configuration": {
			config: []byte(`
auth:
  type: oauth2_client_credentials
  config:
    credentials:
      source: foo
      selector: bar
    token_url: http://foobar.foo
`),
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).
					Return(func() {}, nil)
				sm.EXPECT().ResolveCredentials(mock.Anything, mock.Anything).Return(
					secrettypes.NewCredentials("foo", "bar", map[string]any{
						"client_id":     "foo",
						"client_secret": "bar",
					}), nil)
			},
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &OAuth2ClientCredentials{}, as)
				ccs := as.(*OAuth2ClientCredentials) // nolint: forcetypeassert
				assert.Equal(t, "http://foobar.foo", ccs.TokenURL)
				assert.Empty(t, ccs.Scopes)
				require.NotNil(t, ccs.Header)
				assert.Equal(t, "Authorization", ccs.Header.Name)
				assert.Equal(t, "Bearer", ccs.Header.Scheme)
				assert.Equal(t, clientcredentials.AuthMethod("basic_auth"), ccs.AuthMethod)
				assert.Nil(t, ccs.TTL)
			},
		},
		"with unsupported properties": {
			config: []byte(`
auth:
  type: oauth2_client_credentials
  config:
    credentials:
      source: oauth
      selector: client-creds
    token_url: http://foobar.foo
    foo: bar
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "invalid keys: foo")
			},
		},
		"all possible properties": {
			config: []byte(`
auth:
  type: oauth2_client_credentials
  config:
    credentials:
      source: oauth
      selector: client-creds
    token_url: http://foobar.foo
    auth_method: request_body
    cache_ttl: 1h
    header:
      name: X-Foo
      scheme: Bar
    scopes:
      - foo
      - bar
`),
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).
					Return(func() {}, nil)
				sm.EXPECT().ResolveCredentials(mock.Anything, mock.Anything).Return(
					secrettypes.NewCredentials("foo", "bar", map[string]any{
						"client_id":     "foo",
						"client_secret": "bar",
					}), nil)
			},
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &OAuth2ClientCredentials{}, as)
				ccs := as.(*OAuth2ClientCredentials) // nolint: forcetypeassert
				assert.Equal(t, "http://foobar.foo", ccs.TokenURL)
				assert.Equal(t, []string{"foo", "bar"}, ccs.Scopes)
				require.NotNil(t, ccs.Header)
				assert.Equal(t, "X-Foo", ccs.Header.Name)
				assert.Equal(t, "Bar", ccs.Header.Scheme)
				assert.Equal(t, clientcredentials.AuthMethod("request_body"), ccs.AuthMethod)
				require.NotNil(t, ccs.TTL)
				assert.Equal(t, time.Hour, *ccs.TTL)
				assert.NotNil(t, ccs.resolver)
			},
		},
		"without credentials property": {
			config: []byte(`
auth:
  type: oauth2_client_credentials
  config:
    token_url: http://foobar.foo
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'credentials' is a required field")
			},
		},
		"without credentials source property": {
			config: []byte(`
auth:
  type: oauth2_client_credentials
  config:
    credentials:
      selector: client-creds
    token_url: http://foobar.foo
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'credentials'.'source' is a required field")
			},
		},
		"without token_url property": {
			config: []byte(`
auth:
  type: oauth2_client_credentials
  config:
    credentials:
      source: oauth
      selector: client-creds
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'token_url' is a required field")
			},
		},
		"without config property": {
			config: []byte(`
auth:
  type: oauth2_client_credentials
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'config' property to be set")
			},
		},
		"with enforced but disabled https scheme in token_url": {
			enforceTLS: true,
			config: []byte(`
auth:
  type: oauth2_client_credentials
  config:
    credentials:
      source: oauth
      selector: client-creds
    token_url: http://foobar.foo
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'token_url' scheme must be https")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			es := config.EnforcementSettings{EnforceEgressTLS: tc.enforceTLS}
			validator, err := validation.NewValidator(
				validation.WithTagValidator(es),
				validation.WithErrorTranslator(es),
			)
			require.NoError(t, err)

			setup := x.IfThenElse(tc.setup != nil, tc.setup, func(t *testing.T, _ *secretsmocks.ManagerMock) { t.Helper() })

			sm := secretsmocks.NewManagerMock(t)
			setup(t, sm)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Maybe().Return(log.Logger)
			appCtx.EXPECT().SecretsManager().Maybe().Return(sm)

			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					DecodeAuthenticationStrategyHookFunc(appCtx),
				),
				Result: &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			tc.assert(t, err, typ.AuthStrategy)
		})
	}
}

func TestDecodeAuthenticationStrategyHookFuncForHTTPMessageSignatures(t *testing.T) {
	t.Parallel()

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	secret := secrettypes.NewAsymmetricKeySecret("foo", "bar", "kid-1", privKey, nil)

	type Type struct {
		AuthStrategy endpoint.AuthenticationStrategy `mapstructure:"auth"`
	}

	for uc, tc := range map[string]struct {
		config []byte
		setup  func(t *testing.T, sm *secretsmocks.ManagerMock)
		assert func(t *testing.T, err error, as endpoint.AuthenticationStrategy)
	}{
		"without signer": {
			config: []byte(`
auth:
  type: http_message_signatures
  config:
    components: ["@method"]
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()
				require.Error(t, err)
				require.ErrorContains(t, err, "'signer' is a required field")
			},
		},
		"without secret": {
			config: []byte(`
auth:
  type: http_message_signatures
  config:
    signer:
      name: foo
    components: ["@method"]
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()
				require.Error(t, err)
				require.ErrorContains(t, err, "'signer'.'secret' is a required field")
			},
		},
		"without secret source": {
			config: []byte(`
auth:
  type: http_message_signatures
  config:
    signer:
      secret:
        selector: bar
    components: ["@method"]
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()
				require.Error(t, err)
				require.ErrorContains(t, err, "'signer'.'secret'.'source' is a required field")
			},
		},
		"without component identifiers": {
			config: []byte(`
auth:
  type: http_message_signatures
  config:
    signer:
      secret:
        source: foo
        selector: bar
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()
				require.Error(t, err)
				require.ErrorContains(t, err, "'components' must contain more than 0 items")
			},
		},
		"error while initializing strategy": {
			config: []byte(`
auth:
  type: http_message_signatures
  config:
    components: ["@method"]
    signer:
      secret:
        source: foo
        selector: bar
`),
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving secret")
			},
		},
		"with unsupported properties": {
			config: []byte(`
auth:
  type: http_message_signatures
  config:
    components: ["@method"]
    foo: bar
    signer:
      secret:
        source: foo
        selector: bar
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "invalid keys: foo")
			},
		},
		"minimal possible configuration": {
			config: []byte(`
auth:
  type: http_message_signatures
  config:
    components: ["@method"]
    signer:
      secret:
        source: foo
        selector: bar
`),
			setup: func(t *testing.T, sm *secretsmocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).Return(secret, nil)
				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).Return(func() {}, nil)
			},
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()
				require.NoError(t, err)

				httpSig, ok := as.(*HTTPMessageSignatures)
				require.True(t, ok)
				assert.NotNil(t, httpSig.resolver)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			validator, err := validation.NewValidator()
			require.NoError(t, err)

			setup := x.IfThenElse(tc.setup != nil, tc.setup, func(t *testing.T, _ *secretsmocks.ManagerMock) { t.Helper() })

			sm := secretsmocks.NewManagerMock(t)
			setup(t, sm)

			krm := keyregistrymocks.NewRegistryMock(t)
			krm.EXPECT().Notify(mock.Anything).Maybe()

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().DecoderFactory().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))
			appCtx.EXPECT().Logger().Maybe().Return(log.Logger)
			appCtx.EXPECT().SecretsManager().Maybe().Return(sm)
			appCtx.EXPECT().KeyRegistry().Maybe().Return(krm)

			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					DecodeAuthenticationStrategyHookFunc(appCtx),
				),
				Result: &typ,
			})
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			err = dec.Decode(conf)
			tc.assert(t, err, typ.AuthStrategy)
		})
	}
}

func TestDecodeAuthenticationStrategyHookFuncForUnknownStrategy(t *testing.T) {
	t.Parallel()

	type Type struct {
		AuthStrategy endpoint.AuthenticationStrategy `mapstructure:"auth"`
	}

	// GIVEN
	var typ Type

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			DecodeAuthenticationStrategyHookFunc(nil),
		),
		Result: &typ,
	})
	require.NoError(t, err)

	conf, err := testsupport.DecodeTestConfig([]byte(`
auth:
  type: "foo-bar"
  config:
    foo: bar
`))
	require.NoError(t, err)

	// WHEN
	err = dec.Decode(conf)

	// THEN
	require.Error(t, err)
	require.ErrorContains(t, err, "unsupported authentication type")
}
