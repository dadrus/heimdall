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

// maxHostLen is the upper bound for a valid HTTP Host header value.
// 253 characters for the hostname (RFC 1123) + 1 for ':' + 5 for port (max. 65535).
// For IPv6: "[" + 39 chars (max. uncompressed IPv6) + "]" + 1 + 5 = 47 – well below 261.
const maxHostLen = 261

// IsValidAuthority reports whether authority is safe to use as an HTTP Host
// value for proxying and Forwarded header construction.
//
// This is intentionally a pragmatic ASCII allowlist, not a full DNS/IP
// validator. It accepts hostname-like reg-names, IPv4-like values, and
// bracketed IPv6 literals with an optional port. Its primary purpose is to
// reject Forwarded header delimiters, quoting characters, whitespace, control
// characters, and other bytes that could change the structure of a Forwarded
// header.
//
// In particular, ',' and ';' are rejected to prevent Forwarded header
// element/parameter injection.
func IsValidAuthority(authority string) bool {
	// An empty authority is only permitted for HTTP/1.0 compatibility; we reject it
	// because heimdall does not speak HTTP/1.0.
	l := len(authority)
	if l == 0 || l > maxHostLen {
		return false
	}

	// IPv6 literal: must start with '['
	if authority[0] == '[' {
		return isValidIPv6Authority(authority)
	}

	if authority[0] == '.' || authority[0] == '-' || authority[0] == '_' {
		return false
	}

	return isIPv4OrDNSNameAuthority(authority)
}

// isValidIPv6Authority expects a value in the form "[<addr>]" or "[<addr>]:<port>".
//
//nolint:gocognit, cyclop, gocyclo, funlen
func isValidIPv6Authority(value string) bool {
	end := indexByte(value, ']', 1)
	if end < 0 {
		return false
	}

	if !isIPv6(value[1:end]) {
		return false
	}

	if end+1 == len(value) {
		return true
	}

	return end+2 < len(value) &&
		value[end+1] == ':' &&
		isValidPortFrom(value, end+2)
}

//nolint:gocognit, cyclop, funlen
func isIPv6(value string) bool {
	length := len(value)
	if length < 2 { //nolint:mnd
		return false
	}

	groups := 0
	colons := 0
	groupLen := 0
	groupStart := 0
	doubleColon := false

	for i := 0; i < length; i++ {
		ch := value[i]
		if isHexByte(ch) {
			if groupLen == 0 {
				groupStart = i
			}

			groupLen++
			if groupLen > 4 { //nolint:mnd
				return false
			}

			continue
		}

		if ch == ':' { //nolint:nestif
			if i+1 < length && value[i+1] == ':' {
				if doubleColon {
					return false
				}

				if groupLen > 0 {
					groups++
					groupLen = 0
				}

				doubleColon = true
				colons += 2
				i++

				continue
			}

			if groupLen == 0 || i == length-1 {
				return false
			}

			groups++
			groupLen = 0
			colons++

			continue
		}

		if ch == '.' {
			if !isIPv4(value[groupStart:]) {
				return false
			}

			groups += 2

			if doubleColon {
				return colons >= 2 && groups < 8
			}

			return colons >= 2 && groups == 8
		}

		return false
	}

	if groupLen > 0 {
		groups++
	}

	if doubleColon {
		return colons >= 2 && groups < 8
	}

	return colons >= 2 && groups == 8
}

func isIPv4(value string) bool {
	dots := 0
	num := 0
	digits := 0

	for i := range len(value) {
		ch := value[i]

		if ch >= '0' && ch <= '9' {
			num = num*10 + int(ch-'0') //nolint:mnd
			digits++

			if num > 255 { //nolint:mnd
				return false
			}

			continue
		}

		if ch == '.' {
			if digits == 0 {
				return false
			}
			dots++
			num = 0
			digits = 0

			continue
		}

		return false
	}

	return dots == 3 && digits > 0
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}

//nolint:cyclop
func isIPv4OrDNSNameAuthority(value string) bool {
	hostLen := 0

	for i := range len(value) {
		ch := value[i]

		if (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '.' || ch == '-' || ch == '_' {
			hostLen++

			continue
		}

		if ch == ':' {
			return hostLen > 0 && hostLen <= 253 && isValidPortFrom(value, i+1)
		}

		return false
	}

	return hostLen > 0 && hostLen <= 253
}

func isValidPortFrom(value string, start int) bool {
	portLen := len(value) - start
	if portLen == 0 || portLen > 5 {
		return false
	}

	j := 0
	for i := start; i < len(value); i++ {
		c := value[i]
		if c < '0' || c > '9' {
			return false
		}

		j = j*10 + int(c-'0') //nolint:mnd
	}

	if portLen < 5 { //nolint:mnd
		return j >= 1
	}

	return j >= 1 && j <= 65535
}

func indexByte(value string, c byte, start int) int {
	for i := start; i < len(value); i++ {
		if value[i] == c {
			return i
		}
	}

	return -1
}
