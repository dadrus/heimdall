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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"runtime"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/mocks"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
)

func BenchmarkHTTPMessageSignaturesApply(b *testing.B) {
	for _, tc := range []struct {
		name             string
		components       []string
		populatedHeaders bool
		body             string
	}{
		{
			name:       "derived_component",
			components: []string{"@method"},
		},
		{
			name: "header_components",
			components: []string{
				"@method",
				"content-type",
				"x-tenant-id",
			},
			populatedHeaders: true,
		},
		{
			name:       "content_digest",
			components: []string{"@method", "content-digest"},
			body:       benchmarkRequestBody,
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			strategy := newHTTPMessageSignaturesBenchmarkStrategy(
				b,
				tc.components...,
			)

			base := newAuthStrategyBenchmarkRequest(
				b,
				context.Background(),
				"https://example.com/resource",
				tc.populatedHeaders,
				tc.body,
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

func newHTTPMessageSignaturesBenchmarkStrategy(
	b *testing.B,
	components ...string,
) *HTTPMessageSignatures {
	b.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	secretConfig := config.Secret{
		Source:   "benchmark",
		Selector: "http-message-signatures",
	}

	ref := secrets.Reference{
		Source:   secretConfig.Source,
		Selector: secretConfig.Selector,
	}

	secret := secrettypes.NewAsymmetricKeySecret(
		"http-message-signatures",
		"benchmark",
		privateKey,
		nil,
	)

	resolver := secretsmocks.NewResolverMock(b)
	handle := secretsmocks.NewSecretHandleMock(b)

	resolver.EXPECT().Secret(ref).Return(handle, nil)

	handle.EXPECT().
		OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
			if err := cb(b.Context(), secret); err != nil {
				b.Fatal(err)
			}

			return true
		}))

	registry := keyregistrymocks.NewRegistryMock(b)
	registry.EXPECT().Notify(ref)

	appCtx := app.NewContextMock(b)
	appCtx.EXPECT().SecretResolver().Return(resolver)
	appCtx.EXPECT().KeyRegistry().Return(registry)

	strategy := &HTTPMessageSignatures{
		Signer: SignerConfig{
			Secret: secretConfig,
		},
		Components: components,
	}

	if err := strategy.init(appCtx); err != nil {
		b.Fatal(err)
	}

	return strategy
}
