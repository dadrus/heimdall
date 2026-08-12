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

package authstrategy

import (
	"context"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
)

const benchmarkRequestBody = `{"foo":"bar","tenant":"tenant-a"}`

func newAuthStrategyBenchmarkRequest(
	tb testing.TB,
	ctx context.Context,
	target string,
	populatedHeaders bool,
	body string,
) *http.Request {
	tb.Helper()

	var bodyReader io.Reader
	if len(body) != 0 {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		target,
		bodyReader,
	)
	if err != nil {
		tb.Fatal(err)
	}

	if populatedHeaders {
		populateAuthStrategyBenchmarkHeaders(req)
	}

	return req
}

func populateAuthStrategyBenchmarkHeaders(req *http.Request) {
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

func BenchmarkHeaderCOW(b *testing.B) {
	for _, tc := range []struct {
		name             string
		populatedHeaders bool
	}{
		{
			name: "empty_headers",
		},
		{
			name:             "populated_headers",
			populatedHeaders: true,
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			base := newAuthStrategyBenchmarkRequest(
				b,
				context.Background(),
				"https://example.com/resource?foo=bar&bar=baz&tenant=tenant-a",
				tc.populatedHeaders,
				benchmarkRequestBody,
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				req := *base
				req.Header = req.Header.Clone()

				runtime.KeepAlive(req)
			}
		})
	}
}

func BenchmarkURLCOW(b *testing.B) {
	base := newAuthStrategyBenchmarkRequest(
		b,
		context.Background(),
		"https://example.com/resource?foo=bar&bar=baz&tenant=tenant-a",
		true,
		benchmarkRequestBody,
	)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		req := *base
		targetURL := *req.URL
		req.URL = &targetURL

		runtime.KeepAlive(req)
	}
}
