package hostvalidation

import (
	"testing"
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
		{"[::1]:443", true, "IPv6 loopback with port"},
		{"[2001:db8::1]", true, "IPv6 documentation address"},
		{"[2001:db8::1]:8080", true, "IPv6 with port"},
		{"[::ffff:192.0.2.1]", true, "IPv4-mapped IPv6"},

		// Injection attempts
		{"evil.com,for=127.0.0.1", false, "comma injection (Forwarded)"},
		{"evil.com;for=127.0.0.1", false, "semicolon injection (Forwarded)"},
		{"legit.com;proto=https,for=192.168.1.1", false, "combined injection"},
		{"host\r\nX-Injected: val", false, "CRLF injection"},
		{"host with space", false, "space in host"},
		{"host=value", false, "equals sign"},

		// Invalid formats
		{"", false, "empty string"},
		{":8080", false, "missing hostname"},
		{"example.com:99999", false, "port out of range"},
		{"example.com:0", false, "port zero"},
		{"example.com:abc", false, "non-numeric port"},
		{"[::1", false, "IPv6 missing closing bracket"},
		{"::1", false, "IPv6 without brackets"},
		{"[not-an-ip]", false, "brackets around non-IPv6"},
		{"[192.168.1.1]", false, "brackets around IPv4 (not valid IPv6)"},

		// Length boundary
		{string(make([]byte, maxHostLen+1)), false, "exceeds maxHostLen"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := isValidAuthority(tt.host)
			if got != tt.valid {
				t.Errorf("isValidHost(%q) = %v, want %v", tt.host, got, tt.valid)
			}
		})
	}
}

func TestHelperValidators(t *testing.T) {
	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{"ipv4 valid", isIPv4("192.168.1.1"), true},
		{"ipv4 octet out of range", isIPv4("192.168.1.256"), false},
		{"ipv4 missing octet", isIPv4("192.168.1"), false},
		{"ipv6 valid", isIPv6("2001:db8::1"), true},
		{"ipv6 mapped ipv4", isIPv6("::ffff:192.0.2.1"), true},
		{"ipv6 rejects ipv4", isIPv6("192.168.1.1"), false},
		{"dns valid", isDNSName("api.example.com"), true},
		{"dns underscore", isDNSName("host_with_underscore"), true},
		{"dns rejects comma", isDNSName("evil.com,for=127.0.0.1"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}
