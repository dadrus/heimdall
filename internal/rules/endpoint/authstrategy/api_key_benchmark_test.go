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

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
)

func BenchmarkAPIKeyApply(b *testing.B) {
	for _, tc := range []struct {
		name             string
		in               string
		keyName          string
		target           string
		populatedHeaders bool
	}{
		{
			name:    "header/empty_headers",
			in:      "header",
			keyName: "X-API-Key",
			target:  "https://example.com/resource",
		},
		{
			name:             "header/populated_headers",
			in:               "header",
			keyName:          "X-API-Key",
			target:           "https://example.com/resource",
			populatedHeaders: true,
		},
		{
			name:    "cookie/empty_headers",
			in:      "cookie",
			keyName: "api-key",
			target:  "https://example.com/resource",
		},
		{
			name:             "cookie/populated_headers",
			in:               "cookie",
			keyName:          "api-key",
			target:           "https://example.com/resource",
			populatedHeaders: true,
		},
		{
			name:    "query/empty_query",
			in:      "query",
			keyName: "api_key",
			target:  "https://example.com/resource",
		},
		{
			name:    "query/populated_query",
			in:      "query",
			keyName: "api_key",
			target:  "https://example.com/resource?foo=bar&bar=baz&tenant=tenant-a",
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			strategy := newAPIKeyBenchmarkStrategy(
				b,
				tc.in,
				tc.keyName,
				"secret",
			)

			base := newAuthStrategyBenchmarkRequest(
				b,
				context.Background(),
				tc.target,
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

func newAPIKeyBenchmarkStrategy(
	b *testing.B,
	in string,
	name string,
	value string,
) *APIKey {
	b.Helper()

	secretConfig := config.Secret{
		Source:   "benchmark",
		Selector: "api-key",
	}

	secret := types.NewStringSecret("api-key", value)

	resolver := secretsmocks.NewResolverMock(b)
	handle := secretsmocks.NewSecretHandleMock(b)

	resolver.EXPECT().
		Secret(secrets.Reference{
			Source:   secretConfig.Source,
			Selector: secretConfig.Selector,
		}).
		Return(handle, nil)

	handle.EXPECT().
		OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
			if err := cb(b.Context(), secret); err != nil {
				b.Fatal(err)
			}

			return true
		}))

	appCtx := app.NewContextMock(b)
	appCtx.EXPECT().SecretResolver().Return(resolver)

	strategy := &APIKey{
		In:     in,
		Name:   name,
		Secret: secretConfig,
	}

	if err := strategy.init(appCtx); err != nil {
		b.Fatal(err)
	}

	return strategy
}