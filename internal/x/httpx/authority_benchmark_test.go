// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package httpx

import "testing"

func BenchmarkIsValidAuthority_Hostname(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		IsValidAuthority("api.example.com:8080")
	}
}

func BenchmarkIsValidAuthority_IPv4(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		IsValidAuthority("192.168.1.1:443")
	}
}

func BenchmarkIsValidAuthority_IPv6(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		IsValidAuthority("[2001:db8::1]:8080")
	}
}

func BenchmarkIsValidAuthority_InjectionAttempt(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		IsValidAuthority("evil.com,for=127.0.0.1")
	}
}
