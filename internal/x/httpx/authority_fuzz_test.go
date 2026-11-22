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
	"strings"
	"testing"
)

// This is a structural reference model. It deliberately permits underscores,
// non-DNS reg-names and leading zeroes in port numbers, as the documented
// pragmatic Host allowlist does.
func referenceAuthority(authority string) bool {
	if len(authority) == 0 || len(authority) > maxHostLen {
		return false
	}
	if authority[0] == '[' {
		end := strings.IndexByte(authority, ']')
		if end < 0 || !referenceIP(authority[1:end]) || !strings.Contains(authority[1:end], ":") {
			return false
		}

		return end == len(authority)-1 ||
			(end+1 < len(authority) && authority[end+1] == ':' && referencePort(authority[end+2:]))
	}

	host, port, hasPort := strings.Cut(authority, ":")
	if len(host) == 0 || len(host) > 253 || strings.ContainsAny(host[:1], ".-_") {
		return false
	}

	for i := range len(host) {
		c := host[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}

	return !hasPort || referencePort(port)
}

func referencePort(port string) bool {
	if len(port) == 0 || len(port) > 5 {
		return false
	}

	number := 0
	for i := range len(port) {
		c := port[i]
		if c < '0' || c > '9' {
			return false
		}

		number = number*10 + int(c-'0')
	}

	return number >= 1 && number <= 65535
}

func referenceUpperASCII(value string) string {
	out := []byte(value)
	for i, c := range out {
		if c >= 'a' && c <= 'z' {
			out[i] = c - ('a' - 'A')
		}
	}

	return string(out)
}

func FuzzIsValidAuthority(f *testing.F) {
	for _, host := range []string{
		"example.com", "EXAMPLE.COM:443", "host_with_underscore", "a:00001",
		".example.com", "-example.com", "host:0", "host:65535", "host:65536",
		"host:123456", "host:", "[::1]", "[::]:443", "[2001:db8::1]",
		"[::ffff:192.0.2.1]:443", "[::1]:65536", "[1::2::3]",
		"[::12345]", "[2001:db8:1]", "[::1]junk", "::1",
		"example.com,for=127.0.0.1", "example.com;proto=https",
		"host\r\nForwarded: for=127.0.0.1", "host=value", "host\x00x", "host\xff",
		strings.Repeat("a", 253), strings.Repeat("a", 254),
	} {
		f.Add(host)
	}

	f.Fuzz(func(t *testing.T, authority string) {
		if len(authority) > 8192 {
			return
		}

		actual := IsValidAuthority(authority)
		expected := referenceAuthority(authority)

		if actual != expected {
			t.Fatalf("authority=%q: got %t, reference model wants %t", authority, actual, expected)
		}

		// No accepted Host may contain a delimiter, CR/LF, whitespace,
		// quoting, or any byte that can alter a Forwarded header structure.
		for _, forbidden := range []byte{',', ';', '=', '"', '\\', ' ', '\t', '\r', '\n', 0} {
			mutated := authority + string(forbidden)
			if len(mutated) <= 8192 && IsValidAuthority(mutated) {
				t.Fatalf("accepted authority %q containing forbidden byte %#x", mutated, forbidden)
			}
		}

		// ASCII case has no impact on Host syntax (including IPv6 hex).
		if folded := referenceUpperASCII(authority); IsValidAuthority(folded) != actual {
			t.Fatalf("authority case affected validity: %q -> %q", authority, folded)
		}
	})
}

func TestReferenceAuthorityOracle(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  bool
	}{
		{"example.com", true},
		{"host_with_underscore:443", true},
		{"[::1]", true},
		{"[::ffff:192.0.2.1]", true},
		{"host;for=127.0.0.1", false},
		{"host\r\nx: y", false},
		{"[1::2::3]", false},
		{"[::1]:0", false},
	} {
		if got := referenceAuthority(tc.input); got != tc.want {
			t.Fatalf("oracle authority=%q: got %v, want %v", tc.input, got, tc.want)
		}
	}
}
