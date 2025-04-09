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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	mocks3 "github.com/dadrus/heimdall/internal/otel/metrics/certificate/mocks"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/watcher/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
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
		assert func(t *testing.T, err error, as endpoint.AuthenticationStrategy)
	}{
		"all required properties configured": {
			config: []byte(`
auth:
  type: basic_auth
  config:
    user: foo
    password: bar`),
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &BasicAuth{}, as)
				bas := as.(*BasicAuth) // nolint: forcetypeassert
				assert.Equal(t, "foo", bas.User)
				assert.Equal(t, "bar", bas.Password)
			},
		},
		"with unsupported properties": {
			config: []byte(`
auth:
  type: basic_auth
  config:
    user: foo
    password: bar
    foo: bar
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "invalid keys: foo")
			},
		},
		"without user property": {
			config: []byte(`
auth:
  type: basic_auth
  config:
    password: bar
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'user' is a required field")
			},
		},
		"without password property": {
			config: []byte(`
auth:
  type: basic_auth
  config:
    user: foo
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'password' is a required field")
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

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Return(validator)
			appCtx.EXPECT().Logger().Maybe().Return(log.Logger)

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
		assert func(t *testing.T, err error, as endpoint.AuthenticationStrategy)
	}{
		"all required properties, with in=header": {
			config: []byte(`
auth:
  type: api_key
  config:
    name: foo
    value: bar
    in: header
`),
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &APIKey{}, as)
				aks := as.(*APIKey) // nolint: forcetypeassert
				assert.Equal(t, "foo", aks.Name)
				assert.Equal(t, "bar", aks.Value)
				assert.Equal(t, "header", aks.In)
			},
		},
		"with unsupported properties": {
			config: []byte(`
auth:
  type: api_key
  config:
    name: foo
    value: bar
    in: header
    foo: bar
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "invalid keys: foo")
			},
		},
		"all required properties, with in=cookie": {
			config: []byte(`
auth:
  type: api_key
  config:
    name: foo
    value: bar
    in: cookie
`),
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &APIKey{}, as)
				aks := as.(*APIKey) // nolint: forcetypeassert
				assert.Equal(t, "foo", aks.Name)
				assert.Equal(t, "bar", aks.Value)
				assert.Equal(t, "cookie", aks.In)
			},
		},
		"all required properties, with in=query": {
			config: []byte(`
auth:
  type: api_key
  config:
    name: foo
    value: bar
    in: query
`),
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &APIKey{}, as)
				aks := as.(*APIKey) // nolint: forcetypeassert
				assert.Equal(t, "foo", aks.Name)
				assert.Equal(t, "bar", aks.Value)
				assert.Equal(t, "query", aks.In)
			},
		},
		"all required properties, with in=foobar": {
			config: []byte(`
auth:
  type: api_key
  config:
    name: foo
    value: bar
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
    value: bar
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
    value: bar
    in: header
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'name' is a required field")
			},
		},
		"without value property": {
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
				require.ErrorContains(t, err, "'value' is a required field")
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

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Return(validator)
			appCtx.EXPECT().Logger().Maybe().Return(log.Logger)

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
		assert     func(t *testing.T, err error, as endpoint.AuthenticationStrategy)
	}{
		"all required properties": {
			config: []byte(`
auth:
  type: oauth2_client_credentials
  config:
    client_id: foo
    client_secret: bar
    token_url: http://foobar.foo
`),
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &OAuth2ClientCredentials{}, as)
				ccs := as.(*OAuth2ClientCredentials) // nolint: forcetypeassert
				assert.Equal(t, "foo", ccs.ClientID)
				assert.Equal(t, "bar", ccs.ClientSecret)
				assert.Equal(t, "http://foobar.foo", ccs.TokenURL)
			},
		},
		"with unsupported properties": {
			config: []byte(`
auth:
  type: oauth2_client_credentials
  config:
    client_id: foo
    client_secret: bar
    token_url: http://foobar.foo
    foo: bar
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "invalid keys: foo")
			},
		},
		"all possible properties": {
			config: []byte(`
auth:
  type: oauth2_client_credentials
  config:
    client_id: foo
    client_secret: bar
    token_url: http://foobar.foo
    scopes:
      - foo
      - bar
`),
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &OAuth2ClientCredentials{}, as)
				ccs := as.(*OAuth2ClientCredentials) // nolint: forcetypeassert
				assert.Equal(t, "foo", ccs.ClientID)
				assert.Equal(t, "bar", ccs.ClientSecret)
				assert.Equal(t, "http://foobar.foo", ccs.TokenURL)
				assert.ElementsMatch(t, ccs.Scopes, []string{"foo", "bar"})
			},
		},
		"without client_id property": {
			config: []byte(`
auth:
  type: oauth2_client_credentials
  config:
    client_secret: bar
    token_url: http://foobar.foo
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'client_id' is a required field")
			},
		},
		"without client_secret property": {
			config: []byte(`
auth:
  type: oauth2_client_credentials
  config:
    client_id: foo
    token_url: http://foobar.foo
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'client_secret' is a required field")
			},
		},
		"without token_url property": {
			config: []byte(`
auth:
  type: oauth2_client_credentials
  config:
    client_id: foo
    client_secret: bar
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
    client_id: foo
    client_secret: bar
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

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Return(validator)
			appCtx.EXPECT().Logger().Maybe().Return(log.Logger)

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

	testDir := t.TempDir()

	privKey1, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert1, err := testsupport.NewCertificateBuilder(testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&privKey1.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithSignaturePrivKey(privKey1)).
		Build()
	require.NoError(t, err)

	pemBytes1, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey1, pemx.WithHeader("X-Key-ID", "key1")),
		pemx.WithX509Certificate(cert1),
	)
	require.NoError(t, err)

	pemFile, err := os.Create(filepath.Join(testDir, "keystore.pem"))
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes1)
	require.NoError(t, err)

	type Type struct {
		AuthStrategy endpoint.AuthenticationStrategy `mapstructure:"auth"`
	}

	for uc, tc := range map[string]struct {
		config           []byte
		configureContext func(t *testing.T, ccm *app.ContextMock)
		assert           func(t *testing.T, err error, as endpoint.AuthenticationStrategy)
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
		"without key store": {
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
				require.ErrorContains(t, err, "'signer'.'key_store' is a required field")
			},
		},
		"without key store path": {
			config: []byte(`
auth:
  type: http_message_signatures
  config:
    signer:
      key_store:
        password: foo
    components: ["@method"]
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'signer'.'key_store'.'path' is a required field")
			},
		},
		"without component identifiers": {
			config: []byte(`
auth:
  type: http_message_signatures
  config:
    signer:
      key_store:
        path: /some/file.pem
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
      key_store:
        path: /some/path.pem
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "/some/path.pem")
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
      key_store:
        path: /some/path.pem
`),
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "invalid keys: foo")
			},
		},
		"error while registering signer for updates watching": {
			config: []byte(`
auth:
  type: http_message_signatures
  config:
    components: ["@method"]
    signer:
      key_store:
        path: ` + pemFile.Name() + `
`),
			configureContext: func(t *testing.T, ccm *app.ContextMock) {
				t.Helper()

				watcher := mocks.NewWatcherMock(t)
				watcher.EXPECT().Add(pemFile.Name(), mock.Anything).Return(errors.New("test error"))

				ccm.EXPECT().Watcher().Return(watcher)
			},
			assert: func(t *testing.T, err error, _ endpoint.AuthenticationStrategy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed registering")
			},
		},
		"minimal possible configuration": {
			config: []byte(`
auth:
  type: http_message_signatures
  config:
    components: ["@method"]
    signer:
      key_store:
        path: ` + pemFile.Name() + `
`),
			configureContext: func(t *testing.T, ccm *app.ContextMock) {
				t.Helper()

				watcher := mocks.NewWatcherMock(t)
				watcher.EXPECT().Add(pemFile.Name(), mock.Anything).Return(nil)

				observer := mocks3.NewObserverMock(t)
				observer.EXPECT().Add(mock.Anything)

				ccm.EXPECT().Watcher().Return(watcher)
				ccm.EXPECT().CertificateObserver().Return(observer)
			},
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)

				httpSig, ok := as.(*HTTPMessageSignatures)
				require.True(t, ok)

				assert.NotNil(t, httpSig.signer)
				assert.NotEmpty(t, httpSig.Certificates())
				assert.NotEmpty(t, httpSig.Keys())
				assert.Equal(t, "http message signer", httpSig.Name())
			},
		},
		"full possible configuration": {
			config: []byte(`
auth:
  type: http_message_signatures
  config:
    ttl: 1m
    label: bar
    components: ["@method"]
    signer:
      name: foobar
      key_id: key1
      key_store:
        password: secret
        path: ` + pemFile.Name() + `
`),
			configureContext: func(t *testing.T, ccm *app.ContextMock) {
				t.Helper()

				watcher := mocks.NewWatcherMock(t)
				watcher.EXPECT().Add(pemFile.Name(), mock.Anything).Return(nil)

				observer := mocks3.NewObserverMock(t)
				observer.EXPECT().Add(mock.Anything)

				ccm.EXPECT().Watcher().Return(watcher)
				ccm.EXPECT().CertificateObserver().Return(observer)
			},
			assert: func(t *testing.T, err error, as endpoint.AuthenticationStrategy) {
				t.Helper()

				require.NoError(t, err)

				httpSig, ok := as.(*HTTPMessageSignatures)
				require.True(t, ok)

				assert.NotNil(t, httpSig.signer)
				assert.NotEmpty(t, httpSig.Certificates())
				assert.NotEmpty(t, httpSig.Keys())
				assert.Equal(t, "http message signer", httpSig.Name())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Return(validator)
			appCtx.EXPECT().Logger().Maybe().Return(log.Logger)

			configureContext := x.IfThenElse(tc.configureContext != nil,
				tc.configureContext,
				func(t *testing.T, _ *app.ContextMock) { t.Helper() },
			)
			configureContext(t, appCtx)

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
