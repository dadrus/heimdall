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

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
)

type clientCredentialsBenchmarkCache struct {
	value []byte
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
		strategy         *OAuth2ClientCredentials
		populatedHeaders bool
	}{
		{
			name: "default_header/empty_headers",
			strategy: &OAuth2ClientCredentials{
				Config: clientcredentials.Config{
					TokenURL:     "https://issuer.example.com/token",
					ClientID:     "client",
					ClientSecret: "secret",
					Scopes:       []string{"read", "write"},
				},
			},
		},
		{
			name: "default_header/populated_headers",
			strategy: &OAuth2ClientCredentials{
				Config: clientcredentials.Config{
					TokenURL:     "https://issuer.example.com/token",
					ClientID:     "client",
					ClientSecret: "secret",
					Scopes:       []string{"read", "write"},
				},
			},
			populatedHeaders: true,
		},
		{
			name: "custom_header/empty_headers",
			strategy: &OAuth2ClientCredentials{
				Config: clientcredentials.Config{
					TokenURL:     "https://issuer.example.com/token",
					ClientID:     "client",
					ClientSecret: "secret",
					Scopes:       []string{"read", "write"},
				},
				Header: &HeaderConfig{
					Name:   "X-Access-Token",
					Scheme: "Token",
				},
			},
		},
		{
			name: "custom_header/populated_headers",
			strategy: &OAuth2ClientCredentials{
				Config: clientcredentials.Config{
					TokenURL:     "https://issuer.example.com/token",
					ClientID:     "client",
					ClientSecret: "secret",
					Scopes:       []string{"read", "write"},
				},
				Header: &HeaderConfig{
					Name:   "X-Access-Token",
					Scheme: "Token",
				},
			},
			populatedHeaders: true,
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
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

				if err := tc.strategy.Apply(&req); err != nil {
					b.Fatal(err)
				}

				runtime.KeepAlive(req)
			}
		})
	}
}
