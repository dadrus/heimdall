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
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestDecodeAuthenticationStrategyHookFuncForBasicAuthStrategy(t *testing.T) {
	t.Parallel()

	type Type struct {
		AuthStrategy endpoint.AuthenticationStrategy `mapstructure:"auth"`
	}

	// du to a bug in the linter
	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, as endpoint.AuthenticationStrategy)
	}{
		{
			uc: "basic auth with all required properties",
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
		{
			uc: "basic auth without user property",
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
		{
			uc: "basic auth without password property",
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
		{
			uc: "basic auth without config property",
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
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					DecodeAuthenticationStrategyHookFunc(),
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
	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, as endpoint.AuthenticationStrategy)
	}{
		{
			uc: "api key with all required properties, with in=header",
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
		{
			uc: "api key with all required properties, with in=cookie",
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
		{
			uc: "api key with all required properties, with in=query",
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
		{
			uc: "api key with all required properties, with in=foobar",
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
		{
			uc: "api key without in property",
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
		{
			uc: "api key without name property",
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
		{
			uc: "api key without value property",
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
		{
			uc: "api key without config property",
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
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					DecodeAuthenticationStrategyHookFunc(),
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

	// du to a bug in the linter
	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, as endpoint.AuthenticationStrategy)
	}{
		{
			uc: "client credentials with all required properties",
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
		{
			uc: "client credentials with all possible properties",
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
		{
			uc: "client credentials without client_id property",
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
		{
			uc: "client credentials without client_secret property",
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
		{
			uc: "client credentials without token_url property",
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
		{
			uc: "client credentials without config property",
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
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					DecodeAuthenticationStrategyHookFunc(),
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
			DecodeAuthenticationStrategyHookFunc(),
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
