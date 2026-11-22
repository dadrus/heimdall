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
	"errors"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The reference parsers intentionally use splitting, builders, and netip
// instead of the index-based scanners under test. They model the observable
// results, including the different partial-result contracts on errors.
func referenceIPv4(value string) (string, bool) {
	octets := strings.Split(value, ".")
	if len(octets) != 4 {
		return "", false
	}

	for i, octet := range octets {
		if octet == "" {
			return "", false
		}

		for j := range len(octet) {
			if octet[j] < '0' || octet[j] > '9' {
				return "", false
			}
		}

		digits := strings.TrimLeft(octet, "0")
		if digits == "" {
			digits = "0"
		}

		if len(digits) > 3 {
			return "", false
		}

		number, err := strconv.Atoi(digits)
		if err != nil || number > 255 {
			return "", false
		}

		octets[i] = strconv.Itoa(number)
	}

	return strings.Join(octets, "."), true
}

func referenceIP(value string) bool {
	if !strings.Contains(value, ":") {
		_, ok := referenceIPv4(value)

		return ok
	}

	// The project permits leading zeroes in IPv4 octets, including an IPv4
	// suffix inside IPv6. netip is stricter, so canonicalize that suffix for
	// the independent IPv6 grammar check without changing the result value.
	candidate := value
	if strings.Contains(value, ".") {
		pos := strings.LastIndexByte(value, ':')
		if pos < 0 {
			return false
		}

		suffix, ok := referenceIPv4(value[pos+1:])
		if !ok {
			return false
		}

		candidate = value[:pos+1] + suffix
	}

	ip, err := netip.ParseAddr(candidate)

	return err == nil && ip.Is6() && ip.Zone() == ""
}

func referenceXForwardedFor(dst, headers []string) ([]string, error) {
	result := append([]string(nil), dst...)
	for _, header := range headers {
		for _, element := range strings.Split(header, ",") {
			element = strings.TrimSpace(element)
			if element == "" {
				continue
			}

			if !referenceIP(element) {
				return result, ErrInvalidForwardedIP
			}

			result = append(result, element)
		}
	}

	return result, nil
}

// referenceForwardedFields builds complete parameters before interpreting
// them. Quoted commas and semicolons are not parameter separators.
func referenceForwardedFields(header string) ([]string, error) {
	var fields []string
	var field strings.Builder
	inQuotes, backslash := false, false

	for i := range len(header) {
		ch := header[i]
		if backslash {
			backslash = false
			field.WriteByte(ch)

			continue
		}

		switch {
		case inQuotes && ch == '\\':
			backslash = true
		case ch == '"':
			inQuotes = !inQuotes
		case !inQuotes && (ch == ',' || ch == ';'):
			fields = append(fields, field.String())
			field.Reset()

			continue
		}

		field.WriteByte(ch)
	}

	if inQuotes || backslash {
		return nil, ErrInvalidForwardedIP
	}

	return append(fields, field.String()), nil
}

func referenceUnquoteForwarded(value string) (string, bool) {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return "", false
	}
	var result strings.Builder
	escaped := false
	for i := 1; i < len(value)-1; i++ {
		ch := value[i]

		switch {
		case escaped:
			result.WriteByte(ch)
			escaped = false
		case ch == '\\':
			escaped = true
		default:
			result.WriteByte(ch)
		}
	}

	if escaped {
		return "", false
	}

	return result.String(), true
}

func referenceForwardedForValue(raw string) (string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, ErrInvalidForwardedIP
	}

	quoted := strings.HasPrefix(raw, "\"")
	if quoted {
		var ok bool

		raw, ok = referenceUnquoteForwarded(raw)
		if !ok {
			return "", false, ErrInvalidForwardedIP
		}

		raw = strings.TrimSpace(raw)
		if raw == "" {
			return "", false, ErrInvalidForwardedIP
		}
	}

	if referenceEqualFoldASCII(raw, "unknown") || strings.HasPrefix(raw, "_") {
		return "", false, nil
	}

	if strings.HasPrefix(raw, "[") {
		if !quoted || !strings.HasSuffix(raw, "]") {
			return "", false, ErrInvalidForwardedIP
		}

		raw = raw[1 : len(raw)-1]
	}

	if !referenceIP(raw) {
		return "", false, ErrInvalidForwardedIP
	}

	return raw, true, nil
}

func referenceEqualFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ac, bc := a[i], b[i]
		if ac >= 'A' && ac <= 'Z' {
			ac += 'a' - 'A'
		}

		if bc >= 'A' && bc <= 'Z' {
			bc += 'a' - 'A'
		}

		if ac != bc {
			return false
		}
	}

	return true
}

func referenceForwarded(dst, headers []string) ([]string, error) {
	result := append([]string(nil), dst...)
	for _, header := range headers {
		fields, err := referenceForwardedFields(header)
		if err != nil {
			return nil, ErrInvalidForwardedIP
		}

		for _, field := range fields {
			key, val, hasEquals := strings.Cut(strings.TrimSpace(field), "=")
			if !hasEquals || !referenceEqualFoldASCII(strings.TrimSpace(key), "for") {
				continue
			}

			ip, include, err := referenceForwardedForValue(val)
			if err != nil {
				return nil, ErrInvalidForwardedIP
			}

			if include {
				result = append(result, ip)
			}
		}
	}

	return result, nil
}

func checkForwardedResult(t *testing.T, label string, got []string, gotErr error, want []string, wantErr error) {
	t.Helper()
	if !reflect.DeepEqual(got, want) || !errors.Is(gotErr, wantErr) || (gotErr == nil) != (wantErr == nil) {
		t.Fatalf("%s: got (%q, %v), want (%q, %v)", label, got, gotErr, want, wantErr)
	}
}

func FuzzIPsFromXForwardedFor(f *testing.F) {
	for _, pair := range [][2]string{
		{"192.0.2.1", "2001:db8::1"},
		{"192.0.2.1, 198.51.100.2", ""},
		{"192.0.2.1,invalid", "203.0.113.7"},
		{" , 192.0.2.1,,", "::1"},
		{"000192.0000.2.1", "[::1]"},
		{"unknown", "_hidden"},
		{"192.0.2.1:80", "10.0.0.1"},
		{"::ffff:192.0.2.1", "2001:db8::"},
		{"\x00, 127.0.0.1", "\xff"},
	} {
		f.Add(pair[0], pair[1])
	}

	f.Fuzz(func(t *testing.T, first, second string) {
		if len(first)+len(second) > 8192 {
			return
		}

		dst := []string{"10.0.0.1"}
		for _, headers := range [][]string{{first}, {first, second}} {
			got, err := IPsFromXForwardedFor(append([]string(nil), dst...), headers)
			want, wantErr := referenceXForwardedFor(dst, headers)

			checkForwardedResult(t, "X-Forwarded-For", got, err, want, wantErr)
		}

		// Header field boundaries and comma boundaries are equivalent.
		joined, joinedErr := IPsFromXForwardedFor(dst, []string{first + "," + second})
		separate, separateErr := IPsFromXForwardedFor(dst, []string{first, second})
		checkForwardedResult(t, "X-Forwarded-For fields", joined, joinedErr, separate, separateErr)
	})
}

func FuzzIPsFromForwarded(f *testing.F) {
	for _, pair := range [][2]string{
		{"for=192.0.2.1", `for="[2001:db8::1]"`},
		{`for="192.0.2.\1";proto=https`, "for=unknown"},
		{`host="a,b;c";for=192.0.2.1`, "for=198.51.100.2"},
		{`host="a\",b";for=192.0.2.1`, ""},
		{"For=_hidden, FOR=unknown", "for=127.0.0.1"},
		{"for=192.0.2.1;for=bad", "for=127.0.0.1"},
		{`for="[::ffff:192.0.2.1]"`, `for="[2001:db8::1]:443"`},
		{`for="192.0.2.1\""`, "for=127.0.0.1"},
		{`host="unterminated;for=192.0.2.1`, ""},
		{"for=", "for=192.0.2.1"},
		{"for=192.0.2.1;host=example.test", "for=::1"},
		{"\x00;for=192.0.2.1", "for=\xff"},
	} {
		f.Add(pair[0], pair[1])
	}

	f.Fuzz(func(t *testing.T, first, second string) {
		if len(first)+len(second) > 8192 {
			return
		}

		dst := []string{"10.0.0.1"}
		for _, headers := range [][]string{{first}, {first, second}} {
			got, err := IPsFromForwarded(append([]string(nil), dst...), headers)
			want, wantErr := referenceForwarded(dst, headers)

			checkForwardedResult(t, "Forwarded", got, err, want, wantErr)
		}

		// Adding an unrelated parameter cannot change the extracted IPs
		// when the source is a syntactically complete, valid header.
		base, err := IPsFromForwarded(dst, []string{first})
		if err == nil {
			extended, extendedErr := IPsFromForwarded(dst, []string{first + ";proto=https"})

			checkForwardedResult(t, "Forwarded non-for parameter", extended, extendedErr, base, nil)
		}

		// Valid independent header fields can be combined with a comma.
		_, firstErr := referenceForwarded(nil, []string{first})
		_, secondErr := referenceForwarded(nil, []string{second})
		if firstErr == nil && secondErr == nil {
			joined, joinedErr := IPsFromForwarded(dst, []string{first + "," + second})
			separate, separateErr := IPsFromForwarded(dst, []string{first, second})

			checkForwardedResult(t, "Forwarded fields", joined, joinedErr, separate, separateErr)
		}
	})
}

func TestReferenceForwardedOracles(t *testing.T) {
	// Oracle control cases: these expected values are independent of the
	// production parsers and protect the oracle itself against regressions.
	xff, err := referenceXForwardedFor(nil, []string{"192.0.2.1, ::1"})
	checkForwardedResult(t, "XFF control", xff, err, []string{"192.0.2.1", "::1"}, nil)

	xff, err = referenceXForwardedFor(nil, []string{"192.0.2.1, invalid"})
	checkForwardedResult(t, "XFF partial control", xff, err, []string{"192.0.2.1"}, ErrInvalidForwardedIP)

	forwarded, err := referenceForwarded(nil, []string{`for="[2001:db8::1]";host="a,b"`})
	checkForwardedResult(t, "Forwarded control", forwarded, err, []string{"2001:db8::1"}, nil)

	forwarded, err = referenceForwarded([]string{"existing"}, []string{"for=192.0.2.1;for=bad"})
	checkForwardedResult(t, "Forwarded failure control", forwarded, err, nil, ErrInvalidForwardedIP)
}
