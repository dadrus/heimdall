package urlx

import (
	"testing"
)

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
