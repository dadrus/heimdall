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

package endpoint

import (
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestDecodeAuthenticationStrategyHookFuncForBasicAuthStrategy(t *testing.T) {
	t.Parallel()

	type Type struct {
		AuthStrategy AuthenticationStrategy `mapstructure:"auth"`
	}

	// nolint
	// du to a bug in the linter
	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, as AuthenticationStrategy)
	}{
		{
			uc: "basic auth with all required properties",
			config: []byte(`
auth:
  type: basic_auth
  config:
    user: foo
    password: bar`),
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.NoError(t, err)
				assert.IsType(t, &BasicAuthStrategy{}, as)
				bas := as.(*BasicAuthStrategy)
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
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorContains(t, err, "'user' property to be set")
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
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorContains(t, err, "'password' property to be set")
			},
		},
		{
			uc: "basic auth without config property",
			config: []byte(`
auth:
  type: basic_auth
`),
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorContains(t, err, "'config' property to be set")
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
			assert.NoError(t, err)

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
		AuthStrategy AuthenticationStrategy `mapstructure:"auth"`
	}

	// nolint
	// du to a bug in the linter
	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, as AuthenticationStrategy)
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
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.NoError(t, err)
				assert.IsType(t, &APIKeyStrategy{}, as)
				aks := as.(*APIKeyStrategy)
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
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.NoError(t, err)
				assert.IsType(t, &APIKeyStrategy{}, as)
				aks := as.(*APIKeyStrategy)
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
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.NoError(t, err)
				assert.IsType(t, &APIKeyStrategy{}, as)
				aks := as.(*APIKeyStrategy)
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
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorContains(t, err, "to either 'header', 'cookie', or 'query'")
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
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorContains(t, err, "'in' property to be set")
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
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorContains(t, err, "'name' property to be set")
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
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorContains(t, err, "'value' property to be set")
			},
		},
		{
			uc: "api key without config property",
			config: []byte(`
auth:
  type: api_key
`),
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorContains(t, err, "'config' property to be set")
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
			assert.NoError(t, err)

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
		AuthStrategy AuthenticationStrategy `mapstructure:"auth"`
	}

	// nolint
	// du to a bug in the linter
	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, as AuthenticationStrategy)
	}{
		{
			uc: "client credentials with all required properties",
			config: []byte(`
auth:
  type: client_credentials
  config:
    client_id: foo
    client_secret: bar
    token_url: http://foobar.foo
`),
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.NoError(t, err)
				assert.IsType(t, &ClientCredentialsStrategy{}, as)
				ccs := as.(*ClientCredentialsStrategy)
				assert.Equal(t, "foo", ccs.ClientID)
				assert.Equal(t, "bar", ccs.ClientSecret)
				assert.Equal(t, "http://foobar.foo", ccs.TokenURL)
			},
		},
		{
			uc: "client credentials with all possible properties",
			config: []byte(`
auth:
  type: client_credentials
  config:
    client_id: foo
    client_secret: bar
    token_url: http://foobar.foo
    scopes:
      - foo
      - bar
`),
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.NoError(t, err)
				assert.IsType(t, &ClientCredentialsStrategy{}, as)
				ccs := as.(*ClientCredentialsStrategy)
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
  type: client_credentials
  config:
    client_secret: bar
    token_url: http://foobar.foo
`),
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorContains(t, err, "'client_id' property to be set")
			},
		},
		{
			uc: "client credentials without client_secret property",
			config: []byte(`
auth:
  type: client_credentials
  config:
    client_id: foo
    token_url: http://foobar.foo
`),
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorContains(t, err, "'client_secret' property to be set")
			},
		},
		{
			uc: "client credentials without token_url property",
			config: []byte(`
auth:
  type: client_credentials
  config:
    client_id: foo
    client_secret: bar
`),
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorContains(t, err, "'token_url' property to be set")
			},
		},
		{
			uc: "client credentials without config property",
			config: []byte(`
auth:
  type: client_credentials
`),
			assert: func(t *testing.T, err error, as AuthenticationStrategy) {
				t.Helper()

				assert.Error(t, err)
				assert.ErrorContains(t, err, "'config' property to be set")
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
			assert.NoError(t, err)

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
		AuthStrategy AuthenticationStrategy `mapstructure:"auth"`
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
	assert.ErrorContains(t, err, "unsupported authentication type")
}

func TestDecodeEndpointHookFunc(t *testing.T) {
	t.Parallel()

	type Type struct {
		EP Endpoint `mapstructure:"endpoint"`
	}

	// GIVEN

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, ep Endpoint)
	}{
		{
			uc:     "can decode from just url as string",
			config: []byte(`endpoint: http://foo.bar`),
			assert: func(t *testing.T, err error, ep Endpoint) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "http://foo.bar", ep.URL)
			},
		},
		{
			uc: "can still decode from structured definition",
			config: []byte(`
endpoint:
  url: http://foo.bar
  method: PATCH
`),
			assert: func(t *testing.T, err error, ep Endpoint) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "http://foo.bar", ep.URL)
				assert.Equal(t, "PATCH", ep.Method)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			var typ Type

			dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					DecodeEndpointHookFunc(),
					DecodeAuthenticationStrategyHookFunc(),
				),
				Result: &typ,
			})
			require.NoError(t, err)

			// WHEN
			err = dec.Decode(conf)

			// THEN
			tc.assert(t, err, typ.EP)
		})
	}
}
