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
package urlx

import (
	"testing"
)

func BenchmarkUnescapePathValueDecodeSlash(b *testing.B) {
	for uc, value := range map[string]string{
		"clean":              "api/v1/resource",
		"encoded_upper":      "api%2Fv1%5Bid%5D",
		"encoded_lower":      "api%2fv1%5Bid%5D",
		"encoded_long_mixed": "very%2Flong%2Fpath%2Fwith%2Fmany%2Fparts%5Bid%5D%2Ftail",
	} {
		b.Run(uc, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				_ = UnescapePathValue(value, true)
			}
		})
	}
}

func BenchmarkUnescapePathValuePreserveEncodedSlash(b *testing.B) {
	for uc, value := range map[string]string{
		"clean":              "api/v1/resource",
		"encoded_upper":      "api%2Fv1%5Bid%5D",
		"encoded_lower":      "api%2fv1%5Bid%5D",
		"encoded_long_mixed": "very%2Flong%2Fpath%2Fwith%2Fmany%2Fparts%5Bid%5D%2Ftail",
	} {
		b.Run(uc, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				_ = UnescapePathValue(value, false)
			}
		})
	}
}
