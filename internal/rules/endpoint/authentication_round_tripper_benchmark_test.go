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

package endpoint

import (
	"net/http"
	"runtime"
	"strings"
	"testing"
)

func BenchmarkRequestCopy(b *testing.B) {
	for _, tc := range []struct {
		name      string
		populated bool
	}{
		{
			name: "minimal",
		},
		{
			name:      "populated",
			populated: true,
		},
	} {
		b.Run("shallow/"+tc.name, func(b *testing.B) {
			req := newRequestCopyBenchmarkRequest(b, tc.populated)

			var result http.Request

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				result = *req
			}

			runtime.KeepAlive(result)
		})

		b.Run("clone/"+tc.name, func(b *testing.B) {
			req := newRequestCopyBenchmarkRequest(b, tc.populated)

			var result *http.Request

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				result = req.Clone(req.Context())
			}

			runtime.KeepAlive(result)
		})
	}
}

func newRequestCopyBenchmarkRequest(
	b *testing.B,
	populated bool,
) *http.Request {
	b.Helper()

	req, err := http.NewRequestWithContext(
		b.Context(),
		http.MethodPost,
		"https://example.com/resource?foo=bar&bar=baz&tenant=tenant-a",
		strings.NewReader(`{"foo":"bar","tenant":"tenant-a"}`),
	)
	if err != nil {
		b.Fatal(err)
	}

	if populated {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "heimdall")
		req.Header.Set("X-Request-ID", "01K2E7T0W5M8ZKQKRQZQ4Y5KQZ")
		req.Header.Set("X-Tenant-ID", "tenant-a")
		req.Header.Set(
			"Traceparent",
			"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		)
		req.Header.Add("X-Forwarded-For", "10.0.0.1")
		req.Header.Add("X-Forwarded-For", "10.0.0.2")
		req.Header.Set("Cookie", "session=foobar; locale=en")
	}

	return req
}
