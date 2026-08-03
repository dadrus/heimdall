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
	"strings"
	"testing"
)

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

func BenchmarkPathUnescape(b *testing.B) {
	longPlainPath := "/" + strings.Repeat("segment/", 32) + "resource"
	longEncodedPath := "/api/" + strings.Repeat("%61dmin/", 32) + "users"

	modes := []struct {
		name string
		opts UnescapeOptions
	}{
		{
			name: "all",
			opts: UnescapeOptions{Mode: UnescapeAll},
		},
		{
			name: "all_except_slash",
			opts: UnescapeOptions{Mode: UnescapeAllExceptSlash},
		},
		{
			name: "unreserved",
			opts: UnescapeOptions{Mode: UnescapeUnreserved},
		},
	}

	for _, tc := range []struct {
		name  string
		value string
	}{
		{
			name:  "no_escape_short",
			value: "/api/v1/resource",
		},
		{
			name:  "no_escape_long",
			value: longPlainPath,
		},
		{
			name:  "encoded_slash_upper",
			value: "api%2Fv1",
		},
		{
			name:  "encoded_slash_lower",
			value: "api%2fv1",
		},
		{
			name:  "encoded_non_slash",
			value: "foo%5Bid%5D",
		},
		{
			name:  "encoded_mixed",
			value: "api%2Fv1%5Bid%5D",
		},
		{
			name: "encoded_long_mixed",
			value: "very%2Flong%2Fpath%2Fwith%2Fmany%2F" +
				"parts%5Bid%5D%2Ftail",
		},
		{
			name:  "unreserved_single",
			value: "/api/%61dmin/users",
		},
		{
			name: "unreserved_multiple",
			value: "/%68%74%74%70%73/service/" +
				"%76%31/%75sers/%31%32%33",
		},
		{
			name: "reserved_only_embedded_url",
			value: "/proxy/" +
				"https%3A%2F%2Fexample.com%2Fcallback%3Fcode%3Dabc",
		},
		{
			name: "mixed_embedded_url",
			value: "/proxy/" +
				"%68%74%74%70%73%3A%2F%2Fexample.com%2F" +
				"%63allback%3Fcode%3Dabc",
		},
		{
			name:  "double_encoded",
			value: "/api/%252F/%2561/resource",
		},
		{
			name:  "malformed",
			value: "/api/%ZZ/%2/%/resource",
		},
		{
			name:  "unreserved_long",
			value: longEncodedPath,
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			for _, mode := range modes {
				b.Run(mode.name, func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(len(tc.value)))

					for b.Loop() {
						_ = PathUnescape(tc.value, mode.opts)
					}
				})
			}
		})
	}
}
