package urlx

import "testing"

func BenchmarkPathHasDotSegments(b *testing.B) {
	b.ReportAllocs()

	for uc, path := range map[string]string{
		"clean short path":               "/api/v1/resource",
		"clean long path":                "/api/v1/resource/with/a/longer/path/and/more/segments/for/hot/path/testing",
		"plain dot segments":             "/foo/../admin",
		"encoded dot segment lower case": "/scripts/%2e%2e%2fWindows/System32/cmd.exe",
		"encoded dot segment upper case": "/scripts/%2E%2E%2FWindows/System32/cmd.exe",
		"encoded backslash":              "/scripts/%2E%2E%5CWindows/System32/cmd.exe",
	} {
		b.Run(uc, func(b *testing.B) {
			for b.Loop() {
				_ = PathHasDotSegments(path)
			}
		})
	}
}
