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

func BenchmarkContainsEncodedSlash(b *testing.B) {
	for uc, path := range map[string]string{
		"clean_short":        "/api/v1/resource",
		"clean_long":         "/api/v1/resource/with/a/longer/path/and/more/segments/for/hot/path/testing",
		"encoded_upper":      "/scripts/api%2Fv1/resource",
		"encoded_lower":      "/scripts/api%2fv1/resource",
		"encoded_upper_long": "/very/long/path/with/many/segments/and/an/encoded/slash/%2F/end",
	} {
		b.Run(uc, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				_ = ContainsEncodedSlash(path)
			}
		})
	}
}
