package urlx

import (
	"net/url"
	"strings"
	"testing"
)

const escapedSlashToken = "$$$escaped-slash$$$"

func BenchmarkUnescapePathValueDecodeSlash(b *testing.B) {
	for uc, value := range map[string]string{
		"clean":              "api/v1/resource",
		"encoded_upper":      "api%2Fv1%5Bid%5D",
		"encoded_lower":      "api%2fv1%5Bid%5D",
		"encoded_long_mixed": "very%2Flong%2Fpath%2Fwith%2Fmany%2Fparts%5Bid%5D%2Ftail",
	} {
		b.Run(uc, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				_ = UnescapePathValue(value, true)
			}
		})
	}
}

func BenchmarkCurrentDecodeSlashImplementation(b *testing.B) {
	for uc, value := range map[string]string{
		"clean":              "api/v1/resource",
		"encoded_upper":      "api%2Fv1%5Bid%5D",
		"encoded_lower":      "api%2fv1%5Bid%5D",
		"encoded_long_mixed": "very%2Flong%2Fpath%2Fwith%2Fmany%2Fparts%5Bid%5D%2Ftail",
	} {
		b.Run(uc, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				unescaped, _ := url.PathUnescape(value)
				_ = unescaped
			}
		})
	}
}

func BenchmarkUnescapePathValuePreserveEncodedSlash(b *testing.B) {
	for uc, value := range map[string]string{
		"clean":              "api/v1/resource",
		"encoded_upper":      "api%2Fv1%5Bid%5D",
		"encoded_lower":      "api%2fv1%5Bid%5D",
		"encoded_long_mixed": "very%2Flong%2Fpath%2Fwith%2Fmany%2Fparts%5Bid%5D%2Ftail",
	} {
		b.Run(uc, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				_ = UnescapePathValue(value, false)
			}
		})
	}
}

func BenchmarkCurrentPreserveEncodedSlashImplementation(b *testing.B) {
	for uc, value := range map[string]string{
		"clean":              "api/v1/resource",
		"encoded_upper":      "api%2Fv1%5Bid%5D",
		"encoded_lower":      "api%2fv1%5Bid%5D",
		"encoded_long_mixed": "very%2Flong%2Fpath%2Fwith%2Fmany%2Fparts%5Bid%5D%2Ftail",
	} {
		b.Run(uc, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				unescaped, _ := url.PathUnescape(strings.ReplaceAll(value, "%2F", escapedSlashToken))
				_ = strings.ReplaceAll(unescaped, escapedSlashToken, "%2F")
			}
		})
	}
}
