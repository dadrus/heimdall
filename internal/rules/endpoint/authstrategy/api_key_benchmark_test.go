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
)

func BenchmarkAPIKeyApply(b *testing.B) {
	for _, tc := range []struct {
		name             string
		strategy         *APIKey
		target           string
		populatedHeaders bool
	}{
		{
			name: "header/empty_headers",
			strategy: &APIKey{
				In:    "header",
				Name:  "X-API-Key",
				Value: "secret",
			},
			target: "https://example.com/resource",
		},
		{
			name: "header/populated_headers",
			strategy: &APIKey{
				In:    "header",
				Name:  "X-API-Key",
				Value: "secret",
			},
			target:           "https://example.com/resource",
			populatedHeaders: true,
		},
		{
			name: "cookie/empty_headers",
			strategy: &APIKey{
				In:    "cookie",
				Name:  "api-key",
				Value: "secret",
			},
			target: "https://example.com/resource",
		},
		{
			name: "cookie/populated_headers",
			strategy: &APIKey{
				In:    "cookie",
				Name:  "api-key",
				Value: "secret",
			},
			target:           "https://example.com/resource",
			populatedHeaders: true,
		},
		{
			name: "query/empty_query",
			strategy: &APIKey{
				In:    "query",
				Name:  "api_key",
				Value: "secret",
			},
			target: "https://example.com/resource",
		},
		{
			name: "query/populated_query",
			strategy: &APIKey{
				In:    "query",
				Name:  "api_key",
				Value: "secret",
			},
			target: "https://example.com/resource?foo=bar&bar=baz&tenant=tenant-a",
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
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

				if err := tc.strategy.Apply(&req); err != nil {
					b.Fatal(err)
				}

				runtime.KeepAlive(req)
			}
		})
	}
}
