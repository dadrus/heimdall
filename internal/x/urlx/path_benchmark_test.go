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

import "testing"

func BenchmarkPathHasDotSegments(b *testing.B) {
	b.ReportAllocs()

	for uc, path := range map[string]string{
		"clean short path":               "/api/v1/resource",
		"clean long path":                "/api/v1/resource/with/a/longer/path/and/more/segments/for/hot/path/testing",
		"plain dot segments":             "/foo/../admin",
		"encoded dot segment lower case": "/scripts/%2e%2e%2fWindows/System32/cmd.exe",
		"encoded dot segment upper case": "/scripts/%2E%2E%2FWindows/System32/cmd.exe",
		"encoded backslash":              "/scripts/%2E%2E%5CWindows/System32/cmd.exe",
	} {
		b.Run(uc, func(b *testing.B) {
			for b.Loop() {
				_ = PathHasDotSegments(path)
			}
		})
	}
}

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

func BenchmarkUnescapeDecodeSlash(b *testing.B) {
	for uc, value := range map[string]string{
		"clean":              "api/v1/resource",
		"encoded_upper":      "api%2Fv1%5Bid%5D",
		"encoded_lower":      "api%2fv1%5Bid%5D",
		"encoded_long_mixed": "very%2Flong%2Fpath%2Fwith%2Fmany%2Fparts%5Bid%5D%2Ftail",
	} {
		b.Run(uc, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				_ = Unescape(value, true)
			}
		})
	}
}

func BenchmarkUnescapePreserveEncodedSlash(b *testing.B) {
	for uc, value := range map[string]string{
		"clean":              "api/v1/resource",
		"encoded_upper":      "api%2Fv1%5Bid%5D",
		"encoded_lower":      "api%2fv1%5Bid%5D",
		"encoded_long_mixed": "very%2Flong%2Fpath%2Fwith%2Fmany%2Fparts%5Bid%5D%2Ftail",
	} {
		b.Run(uc, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				_ = Unescape(value, false)
			}
		})
	}
}
