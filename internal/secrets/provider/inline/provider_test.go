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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/secrets/provider/mocks"
	"github.com/dadrus/heimdall/internal/validation"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		conf   map[string]any
		assert func(t *testing.T, err error, prv *inlineProvider)
	}{
		"creates provider": {
			conf: map[string]any{
				"api_token": "secret",
				"github": map[string]any{
					"client_id":     "heimdall",
					"client_secret": "secret",
				},
			},
			assert: func(t *testing.T, err error, prv *inlineProvider) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, providerType, prv.Type())
				require.Empty(t, prv.Dependencies())
				require.False(t, prv.IsNamespaceAware())
			},
		},
		"fails for empty config": {
			conf: map[string]any{},
			assert: func(t *testing.T, err error, _ *inlineProvider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "must not be empty")
			},
		},
		"fails for non-string secret value": {
			conf: map[string]any{"api_token": 42},
			assert: func(t *testing.T, err error, _ *inlineProvider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "must be either string or structured object")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			prv, err := newProvider(provider.Args{
				Config: tc.conf,
			})

			var iPrv *inlineProvider
			if err == nil {
				iPrv = prv.(*inlineProvider)
			}

			tc.assert(t, err, iPrv)
		})
	}
}

func TestProviderGetSecret(t *testing.T) {
	t.Parallel()

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))

	prv, err := newProvider(provider.Args{
		Config: map[string]any{
			"api_token": "secret",
			"github": map[string]any{
				"client_id":     "heimdall",
				"client_secret": "secret",
			},
		},
		DecoderFactory: df,
		Observer:       mocks.NewChangeObserverMock(t),
	})
	require.NoError(t, err)

	require.NoError(t, prv.Start(t.Context()))

	t.Cleanup(func() {
		_ = prv.Stop(context.Background())
	})

	for uc, tc := range map[string]struct {
		selector provider.Selector
		assert   func(t *testing.T, err error, secret provider.Secret)
	}{
		"no secret for selector": {
			selector: provider.Selector{Value: "github"},
			assert: func(t *testing.T, err error, _ provider.Secret) {
				t.Helper()

				require.ErrorIs(t, err, provider.ErrSecretNotFound)
				require.ErrorContains(t, err, "selector 'github'")
			},
		},
		"successful": {
			selector: provider.Selector{Value: "api_token"},
			assert: func(t *testing.T, err error, secret provider.Secret) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, secret)
				assert.Equal(t, "api_token", secret.Selector())
				assert.Equal(t, provider.SecretKindString, secret.Kind())

				stringSecret, ok := secret.(provider.StringSecret)
				require.True(t, ok)
				require.Equal(t, "secret", stringSecret.Value())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			secret, err := prv.GetSecret(t.Context(), tc.selector)

			tc.assert(t, err, secret)
		})
	}
}

func TestProviderGetSecretSet(t *testing.T) {
	t.Parallel()

	prv := &inlineProvider{}

	_, err := prv.GetSecretSet(t.Context(), provider.Selector{})

	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
}

func TestProviderGetCredentials(t *testing.T) {
	t.Parallel()

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))

	prv, err := newProvider(provider.Args{
		Config: map[string]any{
			"api_token": "secret",
			"github": map[string]any{
				"client_id":     "heimdall",
				"client_secret": "secret",
			},
		},
		DecoderFactory: df,
		Observer:       mocks.NewChangeObserverMock(t),
	})
	require.NoError(t, err)

	require.NoError(t, prv.Start(t.Context()))

	t.Cleanup(func() {
		_ = prv.Stop(context.Background())
	})

	for uc, tc := range map[string]struct {
		selector provider.Selector
		assert   func(t *testing.T, err error, secret provider.Credentials)
	}{
		"no secret for selector": {
			selector: provider.Selector{Value: "api_token"},
			assert: func(t *testing.T, err error, _ provider.Credentials) {
				t.Helper()

				require.ErrorIs(t, err, provider.ErrCredentialsNotFound)
				require.ErrorContains(t, err, "selector 'api_token'")
			},
		},
		"successful": {
			selector: provider.Selector{Value: "github"},
			assert: func(t *testing.T, err error, creds provider.Credentials) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, creds)
				assert.Equal(t, "github", creds.Selector())

				require.Equal(t, map[string]any{"client_id": "heimdall", "client_secret": "secret"}, creds.Values())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			creds, err := prv.GetCredentials(t.Context(), tc.selector)

			tc.assert(t, err, creds)
		})
	}
}

func TestProviderGetCertificateBundle(t *testing.T) {
	t.Parallel()

	prv := &inlineProvider{}

	_, err := prv.GetCertificateBundle(t.Context(), provider.Selector{})

	require.ErrorIs(t, err, provider.ErrUnsupportedOperation)
}
