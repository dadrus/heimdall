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
			strategy := &BasicAuth{
				User:     "client",
				Password: "secret",
			}

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
