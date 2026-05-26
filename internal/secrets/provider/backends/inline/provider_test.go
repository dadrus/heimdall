// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package inline

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/secrets/registry"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		conf   map[string]any
		assert func(t *testing.T, err error, provider provider.Provider)
	}{
		"creates provider": {
			conf: map[string]any{
				"api_token": "secret",
				"github": map[string]any{
					"client_id":     "heimdall",
					"client_secret": "secret",
				},
			},
			assert: func(t *testing.T, err error, provider provider.Provider) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, ProviderType, provider.Type())
			},
		},
		"fails for empty config": {
			conf: map[string]any{},
			assert: func(t *testing.T, err error, _ provider.Provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "must not be empty")
			},
		},
		"fails for non-string secret value": {
			conf: map[string]any{"api_token": 42},
			assert: func(t *testing.T, err error, _ provider.Provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "must be either string or structured object")
			},
		},
		"fails for selector containing slash": {
			conf: map[string]any{"api/token": "secret"},
			assert: func(t *testing.T, err error, _ provider.Provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "must not contain '/'")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			prv, err := newProvider(provider.Args{
				Config: tc.conf,
			})

			tc.assert(t, err, prv)
		})
	}
}

func TestProviderResolveSecret(t *testing.T) {
	t.Parallel()

	prv, err := newProvider(provider.Args{
		Config: map[string]any{
			"api_token": "secret",
			"api_other": "other",
			"github": map[string]any{
				"client_id":     "heimdall",
				"client_secret": "secret",
			},
		},
	})
	require.NoError(t, err)

	secret, err := prv.GetSecret(t.Context(), provider.Selector{Value: "api_token"})
	require.NoError(t, err)

	stringSecret, ok := secret.(provider.StringSecret)
	require.True(t, ok)
	require.Equal(t, "api_token", stringSecret.Selector())
	require.Equal(t, provider.SecretKindString, stringSecret.Kind())
	require.Equal(t, "secret", stringSecret.Value())
}

func TestProviderResolveSecretSet(t *testing.T) {
	t.Parallel()

	prv, err := newProvider(provider.Args{
		Config: map[string]any{
			"api_token": "secret",
			"api_other": "other",
			"github": map[string]any{
				"client_id":     "heimdall",
				"client_secret": "secret",
			},
		},
	})
	require.NoError(t, err)

	secrets, err := prv.GetSecretSet(t.Context(), provider.Selector{})
	require.NoError(t, err)
	require.Len(t, secrets, 2)

	bySelector := make(map[string]provider.Secret, len(secrets))
	for _, secret := range secrets {
		bySelector[secret.Selector()] = secret
	}

	require.Contains(t, bySelector, "api_token")
	require.Contains(t, bySelector, "api_other")
}

func TestProviderResolveSecretSetNonRootUnsupported(t *testing.T) {
	t.Parallel()

	prv, err := newProvider(provider.Args{
		Config: map[string]any{
			"api_token": "secret",
			"api_other": "other",
			"github": map[string]any{
				"client_id":     "heimdall",
				"client_secret": "secret",
			},
		},
	})
	require.NoError(t, err)

	secrets, err := prv.GetSecretSet(t.Context(), provider.Selector{Value: "api_token"})
	require.Nil(t, secrets)
	require.Error(t, err)
	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
	require.ErrorContains(t, err, "provider root")
}

func TestProviderResolveCredentials(t *testing.T) {
	t.Parallel()

	prv, err := newProvider(provider.Args{
		Config: map[string]any{
			"api_token": "secret",
			"api_other": "other",
			"github": map[string]any{
				"client_id":     "heimdall",
				"client_secret": "secret",
			},
		},
	})
	require.NoError(t, err)

	credentials, err := prv.GetCredentials(t.Context(), provider.Selector{Value: "github"})
	require.NoError(t, err)
	require.Equal(t, "github", credentials.Selector())

	require.Equal(t, map[string]any{
		"client_id":     "heimdall",
		"client_secret": "secret",
	}, credentials.Values())
}

func TestProviderResolveMissing(t *testing.T) {
	t.Parallel()

	prv, err := newProvider(provider.Args{
		Config: map[string]any{
			"api_token": "secret",
			"api_other": "other",
			"github": map[string]any{
				"client_id":     "heimdall",
				"client_secret": "secret",
			},
		},
	})
	require.NoError(t, err)

	secret, err := prv.GetSecret(t.Context(), provider.Selector{Value: "missing"})
	require.Nil(t, secret)
	require.Error(t, err)
	require.ErrorIs(t, err, provider.ErrSecretNotFound)
	require.ErrorContains(t, err, "selector 'missing'")

	credentials, err := prv.GetCredentials(t.Context(), provider.Selector{Value: "missing"})
	require.Nil(t, credentials)
	require.Error(t, err)
	require.ErrorIs(t, err, provider.ErrCredentialsNotFound)
	require.ErrorContains(t, err, "selector 'missing'")
}

func TestProviderStartStop(t *testing.T) {
	t.Parallel()

	prv, err := newProvider(provider.Args{
		Config: map[string]any{
			"api_token": "secret",
			"api_other": "other",
			"github": map[string]any{
				"client_id":     "heimdall",
				"client_secret": "secret",
			},
		},
	})
	require.NoError(t, err)

	require.NoError(t, prv.Start(t.Context()))
	require.NoError(t, prv.Stop(t.Context()))
}

func TestRegistryCreate(t *testing.T) {
	t.Parallel()

	prv, err := registry.Create(ProviderType, provider.Args{
		Config: map[string]any{
			"api_token": "secret",
		},
	})

	require.NoError(t, err)
	require.Equal(t, ProviderType, prv.Type())
}
