package authorityvalidation

import "testing"

func BenchmarkIsValidAuthority_Hostname(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		isValidAuthority("api.example.com:8080")
	}
}

func BenchmarkIsValidAuthority_IPv4(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		isValidAuthority("192.168.1.1:443")
	}
}

func BenchmarkIsValidAuthority_IPv6(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		isValidAuthority("[2001:db8::1]:8080")
	}
}

func BenchmarkIsValidAuthority_InjectionAttempt(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		isValidAuthority("evil.com,for=127.0.0.1")
	}
}
