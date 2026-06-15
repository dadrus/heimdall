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

package httpx

import (
	"testing"
)

func BenchmarkIPsFromXForwardedFor_SingleIPv4(b *testing.B) {
	values := []string{"192.0.2.1"}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromXForwardedFor(dst[:0], values)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIPsFromXForwardedFor_ThreeIPv4s(b *testing.B) {
	values := []string{"192.0.2.1, 198.51.100.2, 203.0.113.3"}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromXForwardedFor(dst[:0], values)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIPsFromXForwardedFor_MultipleHeaderValues(b *testing.B) {
	values := []string{"192.0.2.1", "198.51.100.2", "203.0.113.3"}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromXForwardedFor(dst[:0], values)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIPsFromXForwardedFor_IPv6(b *testing.B) {
	values := []string{"2001:db8::1, 2001:db8::2"}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromXForwardedFor(dst[:0], values)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIPsFromXForwardedFor_InvalidLate(b *testing.B) {
	values := []string{"192.0.2.1, 198.51.100.2, invalid"}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromXForwardedFor(dst[:0], values)
		if err == nil {
			b.Fatal("expected error")
		}
	}
}

func BenchmarkIPsFromForwarded_SingleIPv4(b *testing.B) {
	values := []string{"for=192.0.2.1"}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromForwarded(dst[:0], values)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIPsFromForwarded_ThreeIPv4s(b *testing.B) {
	values := []string{"for=192.0.2.1;proto=https;host=example.com, for=198.51.100.2;proto=https, for=203.0.113.3"}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromForwarded(dst[:0], values)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIPsFromForwarded_MultipleHeaderValues(b *testing.B) {
	values := []string{"for=192.0.2.1", "for=198.51.100.2", "for=203.0.113.3"}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromForwarded(dst[:0], values)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIPsFromForwarded_QuotedIPv4(b *testing.B) {
	values := []string{`for="192.0.2.1"`}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromForwarded(dst[:0], values)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIPsFromForwarded_QuotedIPv6(b *testing.B) {
	values := []string{`for="[2001:db8::1]"`}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromForwarded(dst[:0], values)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIPsFromForwarded_QuotedSeparators(b *testing.B) {
	values := []string{`for=192.0.2.1;host="a,b;c.example";proto=https, for=198.51.100.2`}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromForwarded(dst[:0], values)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIPsFromForwarded_IgnoresUnknownAndObfuscated(b *testing.B) {
	values := []string{`for=unknown, for=_hidden, for=192.0.2.1`}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromForwarded(dst[:0], values)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIPsFromForwarded_InvalidLate(b *testing.B) {
	values := []string{`for=192.0.2.1;proto=https, for=invalid`}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromForwarded(dst[:0], values)
		if err == nil {
			b.Fatal("expected error")
		}
	}
}

func BenchmarkIPsFromForwarded_EscapedQuotedString(b *testing.B) {
	values := []string{`for="192.0.2.\1"`}
	dst := make([]string, 0, 4)

	var err error

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		dst, err = IPsFromForwarded(dst[:0], values)
		if err != nil {
			b.Fatal(err)
		}
	}
}
