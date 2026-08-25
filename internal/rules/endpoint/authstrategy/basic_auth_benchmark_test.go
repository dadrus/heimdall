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
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/validation"
)

func BenchmarkBasicAuthApply(b *testing.B) {
	for _, tc := range []struct {
		name             string
		populatedHeaders bool
	}{
		{
			name: "empty_headers",
		},
		{
			name:             "populated_headers",
			populatedHeaders: true,
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			strategy := newBasicAuthBenchmarkStrategy(
				b,
				"client",
				"secret",
			)

			base := newAuthStrategyBenchmarkRequest(
				b,
				context.Background(),
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

func newBasicAuthBenchmarkStrategy(
	b *testing.B,
	userID string,
	password string,
) *BasicAuth {
	b.Helper()

	credentialsConfig := config.Secret{
		Source:   "benchmark",
		Selector: "basic-auth",
	}

	credentials := types.NewCredentials(
		"basic-auth",
		map[string]any{
			"user_id":  userID,
			"password": password,
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

	appCtx.EXPECT().
		SecretResolver().
		Return(resolver)

	appCtx.EXPECT().
		DecoderFactory().
		Maybe().
		Return(
			encoding.NewDecoderFactory(
				encoding.ValidatorFunc(validator.ValidateStruct),
			),
		)

	strategy := &BasicAuth{
		Credentials: credentialsConfig,
	}

	if err := strategy.init(appCtx); err != nil {
		b.Fatal(err)
	}

	return strategy
}
