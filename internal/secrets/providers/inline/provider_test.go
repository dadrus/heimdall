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
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		conf   map[string]any
		assert func(t *testing.T, err error, provider types.Provider)
	}{
		"creates provider": {
			conf: map[string]any{
				"api/token": "secret",
				"oauth/github": map[string]any{
					"client_id":     "heimdall",
					"client_secret": "secret",
				},
			},
			assert: func(t *testing.T, err error, provider types.Provider) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, "inline-defaults", provider.Name())
				require.Equal(t, ProviderType, provider.Type())
			},
		},
		"fails for empty config": {
			conf: map[string]any{},
			assert: func(t *testing.T, err error, _ types.Provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, types.ErrInvalidSecretPayload)
				require.ErrorContains(t, err, "must not be empty")
			},
		},
		"fails for non-string secret value": {
			conf: map[string]any{"api/token": 42},
			assert: func(t *testing.T, err error, _ types.Provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, types.ErrInvalidSecretPayload)
				require.ErrorContains(t, err, "api/token")
			},
		},
		"fails for non-string credential value": {
			conf: map[string]any{
				"oauth/github": map[string]any{"client_id": 42},
			},
			assert: func(t *testing.T, err error, _ types.Provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, types.ErrInvalidSecretPayload)
				require.ErrorContains(t, err, "oauth/github/client_id")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			provider, err := newProvider(app.NewContextMock(t), "inline-defaults", tc.conf)

			tc.assert(t, err, provider)
		})
	}
}

func TestProviderResolveSecret(t *testing.T) {
	t.Parallel()

	provider := newTestProvider(t)

	secret, err := provider.ResolveSecret(context.Background(), types.Selector{Value: "api/token"})
	require.NoError(t, err)

	stringSecret, ok := secret.(types.StringSecret)
	require.True(t, ok)
	require.Equal(t, "inline-defaults", stringSecret.Source())
	require.Equal(t, "api/token", stringSecret.Selector())
	require.Equal(t, types.SecretKindString, stringSecret.Kind())
	require.Equal(t, "secret", stringSecret.String())
}

func TestProviderResolveSecretSet(t *testing.T) {
	t.Parallel()

	provider := newTestProvider(t)

	secrets, err := provider.ResolveSecretSet(context.Background(), types.Selector{})
	require.NoError(t, err)
	require.Len(t, secrets, 2)

	bySelector := make(map[string]types.Secret, len(secrets))
	for _, secret := range secrets {
		bySelector[secret.Selector()] = secret
	}

	require.Contains(t, bySelector, "api/token")
	require.Contains(t, bySelector, "api/other")
}

func TestProviderResolveCredentials(t *testing.T) {
	t.Parallel()

	type oauthCredentials struct {
		ClientID     string `mapstructure:"client_id"`
		ClientSecret string `mapstructure:"client_secret"`
	}

	provider := newTestProvider(t)

	credentials, err := provider.ResolveCredentials(context.Background(), types.Selector{Value: "oauth/github"})
	require.NoError(t, err)
	require.Equal(t, "inline-defaults", credentials.Source())
	require.Equal(t, "oauth/github", credentials.Selector())

	var decoded oauthCredentials
	require.NoError(t, credentials.Decode(&decoded))
	require.Equal(t, "heimdall", decoded.ClientID)
	require.Equal(t, "secret", decoded.ClientSecret)
}

func TestProviderResolveMissing(t *testing.T) {
	t.Parallel()

	provider := newTestProvider(t)

	secret, err := provider.ResolveSecret(context.Background(), types.Selector{Value: "missing"})
	require.Nil(t, secret)
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrSecretNotFound)
	require.ErrorContains(t, err, "selector 'missing'")

	credentials, err := provider.ResolveCredentials(context.Background(), types.Selector{Value: "missing"})
	require.Nil(t, credentials)
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrSecretNotFound)
	require.ErrorContains(t, err, "selector 'missing'")
}

func TestProviderStartStop(t *testing.T) {
	t.Parallel()

	provider := newTestProvider(t)

	require.NoError(t, provider.Start(context.Background(), nil))
	require.NoError(t, provider.Stop(context.Background()))
}

func TestRegistryCreate(t *testing.T) {
	t.Parallel()

	provider, err := registry.Create(app.NewContextMock(t), ProviderType, "inline-defaults", map[string]any{
		"api/token": "secret",
	})

	require.NoError(t, err)
	require.Equal(t, "inline-defaults", provider.Name())
	require.Equal(t, ProviderType, provider.Type())
}

func newTestProvider(t *testing.T) types.Provider {
	t.Helper()

	provider, err := newProvider(app.NewContextMock(t), "inline-defaults", map[string]any{
		"api/token": "secret",
		"api/other": "other",
		"oauth/github": map[string]any{
			"client_id":     "heimdall",
			"client_secret": "secret",
		},
	})
	require.NoError(t, err)

	return provider
}
