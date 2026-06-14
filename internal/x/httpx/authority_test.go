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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidAuthority(t *testing.T) {
	tests := []struct {
		host  string
		valid bool
		desc  string
	}{
		// Valid hostnames
		{"example.com", true, "plain hostname"},
		{"example.com:8080", true, "hostname with port"},
		{"sub.domain.co.uk", true, "multi-label hostname"},
		{"my-host.internal", true, "hyphen in hostname"},
		{"host_with_underscore", true, "underscore (pragmatic allowlist)"},
		{"localhost", true, "localhost"},
		{"localhost:3000", true, "localhost with port"},
		{"xn--nxasmq6b.com", true, "IDN/punycode"},

		// Valid IPv4
		{"192.168.1.1", true, "IPv4"},
		{"192.168.1.1:80", true, "IPv4 with port"},
		{"0.0.0.0", true, "IPv4 zero address"},
		{"127.0.0.1:443", true, "loopback with port"},

		// Valid IPv6
		{"[::1]", true, "IPv6 loopback without port"},
		{"[::]", true, "IPv6 all-zeros compressed"},
		{"[1::]", true, "IPv6 trailing double colon"},
		{"[::1]:443", true, "IPv6 loopback with port"},
		{"[2001:db8::1]", true, "IPv6 documentation address"},
		{"[2001:db8::1]:8080", true, "IPv6 with port"},
		{"[::1]:65535", true, "IPv6 with maximum valid port"},
		{"[::ffff:192.0.2.1]", true, "IPv4-mapped IPv6"},
		{"[2001:db8:85a3:0:0:8a2e:370:7334]", true, "IPv6 full 8-group address without double colon"},

		// Injection attempts
		{"evil.com,for=127.0.0.1", false, "comma injection (Forwarded)"},
		{"evil.com;for=127.0.0.1", false, "semicolon injection (Forwarded)"},
		{"legit.com;proto=https,for=192.168.1.1", false, "combined injection"},
		{"host\r\nX-Injected: val", false, "CRLF injection"},
		{"host with space", false, "space in host"},
		{"host=value", false, "equals sign"},

		// Invalid formats
		{"", false, "empty string"},
		{".", false, "dot as host name"},
		{"..", false, "two dots as host name"},
		{"_", false, "underscore as host name"},
		{".example.com", false, "leading dot domain name"},
		{"-example.com", false, "leading dash in hostname"},
		{":8080", false, "missing hostname"},
		{"example.com:99999", false, "port out of range"},
		{"example.com:65535", true, "maximum valid port"},
		{"example.com:65536", false, "port just above maximum"},
		{"example.com:123456", false, "port with more than 5 digits"},
		{"example.com:0", false, "port zero"},
		{"example.com:abc", false, "non-numeric port"},
		{"host:", false, "hostname with empty port"},
		{"[::1", false, "IPv6 missing closing bracket"},
		{"::1", false, "IPv6 without brackets"},
		{"[1]", false, "IPv6 single group without any colon"},
		{"[2001:db8:1]", false, "IPv6 incomplete groups without double colon"},
		{"[not-an-ip]", false, "brackets around non-IPv6"},
		{"[::1:2:3:4:5:6:7:8]", false, "IPv6 double colon with too many groups"},
		{"[1::2::3]", false, "IPv6 multiple double colons"},
		{"[::12345]", false, "IPv6 hex group exceeds 4 digits"},
		{"[:1]", false, "IPv6 single colon at start"},
		{"[::1]junk", false, "IPv6 literal with invalid suffix after bracket"},
		{"[::1]:", false, "IPv6 literal with empty port"},
		{"[::1]:0", false, "IPv6 with zero port"},
		{"[192.168.1.1]", false, "brackets around IPv4 (not valid IPv6)"},

		// Length boundary
		{string(make([]byte, maxHostLen+1)), false, "exceeds maxHostLen"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := IsValidAuthority(tt.host)

			assert.Equal(t, tt.valid, got)
		})
	}
}
