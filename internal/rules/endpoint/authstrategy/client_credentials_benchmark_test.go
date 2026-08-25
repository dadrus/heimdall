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

package authstrategy

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/validation"
)

type clientCredentialsBenchmarkCache struct {
	value []byte
}

func (*clientCredentialsBenchmarkCache) Type() string {
	return "benchmark"
}

func (*clientCredentialsBenchmarkCache) Start(context.Context) error {
	return nil
}

func (*clientCredentialsBenchmarkCache) Stop(context.Context) error {
	return nil
}

func (c *clientCredentialsBenchmarkCache) Get(context.Context, string) ([]byte, error) {
	return c.value, nil
}

func (*clientCredentialsBenchmarkCache) Set(
	context.Context,
	string,
	[]byte,
	time.Duration,
) error {
	return nil
}

func BenchmarkOAuth2ClientCredentialsApply(b *testing.B) {
	rawToken, err := json.Marshal(clientcredentials.TokenInfo{
		AccessToken: "foobar",
		TokenType:   "Bearer",
	})
	if err != nil {
		b.Fatal(err)
	}

	ctx := cache.WithContext(
		context.Background(),
		&clientCredentialsBenchmarkCache{value: rawToken},
	)

	for _, tc := range []struct {
		name             string
		header           *headerConfig
		populatedHeaders bool
	}{
		{
			name: "default_header/empty_headers",
		},
		{
			name:             "default_header/populated_headers",
			populatedHeaders: true,
		},
		{
			name: "custom_header/empty_headers",
			header: &headerConfig{
				Name:   "X-Access-Token",
				Scheme: "Token",
			},
		},
		{
			name: "custom_header/populated_headers",
			header: &headerConfig{
				Name:   "X-Access-Token",
				Scheme: "Token",
			},
			populatedHeaders: true,
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			strategy := newOAuth2ClientCredentialsBenchmarkStrategy(
				b,
				tc.header,
			)

			base := newAuthStrategyBenchmarkRequest(
				b,
				ctx,
				"https://example.com/resource",
				tc.populatedHeaders,
				"",
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				req := *base

				if err := strategy.Apply(&req); err != nil {
					b.Fatal(err)
				}

				runtime.KeepAlive(req)
			}
		})
	}
}

func newOAuth2ClientCredentialsBenchmarkStrategy(
	b *testing.B,
	header *headerConfig,
) *OAuth2ClientCredentials {
	b.Helper()

	credentialsConfig := config.Secret{
		Source:   "benchmark",
		Selector: "oauth2-client-credentials",
	}

	credentials := types.NewCredentials(
		"oauth2-client-credentials",
		map[string]any{
			"client_id":     "client",
			"client_secret": "secret",
		},
	)

	resolver := secretsmocks.NewResolverMock(b)
	handle := secretsmocks.NewCredentialsHandleMock(b)

	resolver.EXPECT().
		Credentials(secrets.Reference{
			Source:   credentialsConfig.Source,
			Selector: credentialsConfig.Selector,
		}).
		Return(handle, nil)

	handle.EXPECT().
		OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
			if err := cb(b.Context(), credentials); err != nil {
				b.Fatal(err)
			}

			return true
		}))

	validator, err := validation.NewValidator(
		validation.WithTagValidator(config.EnforcementSettings{}),
	)
	if err != nil {
		b.Fatal(err)
	}

	appCtx := app.NewContextMock(b)
	appCtx.EXPECT().SecretResolver().Return(resolver)
	appCtx.EXPECT().DecoderFactory().Maybe().
		Return(
			encoding.NewDecoderFactory(
				encoding.ValidatorFunc(validator.ValidateStruct),
			),
		)

	strategy := &OAuth2ClientCredentials{
		TokenURL:    "https://issuer.example.com/token",
		Credentials: credentialsConfig,
		AuthMethod:  clientcredentials.AuthMethodBasicAuth,
		Scopes:      []string{"read", "write"},
		Header:      header,
	}

	if err := strategy.init(appCtx); err != nil {
		b.Fatal(err)
	}

	return strategy
}
