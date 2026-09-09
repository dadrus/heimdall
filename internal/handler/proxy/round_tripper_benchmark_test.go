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

package proxy

import (
	"net/http"
	"testing"
)

func BenchmarkProfileRoundTripperTransportFor(b *testing.B) {
	rt := &profileRoundTripper{
		normal:        new(http.Transport),
		http1Only:     new(http.Transport),
		http2Required: new(http.Transport),
	}

	for name, tc := range map[string]struct {
		request  *requestContext
		expected *http.Transport
	}{
		"normal": {
			request: &requestContext{
				upstreamScheme: upstreamSchemeHTTPS,
			},
			expected: rt.normal,
		},
		"http1 only": {
			request: &requestContext{
				upstreamScheme: upstreamSchemeHTTPS,
				upgrade:        true,
			},
			expected: rt.http1Only,
		},
		"http2 required grpc": {
			request: &requestContext{
				upstreamScheme: upstreamSchemeHTTPS,
				nativeGRPC:     true,
			},
			expected: rt.http2Required,
		},
		"http2 required h2c": {
			request: &requestContext{
				upstreamScheme: upstreamSchemeH2C,
			},
			expected: rt.http2Required,
		},
	} {
		b.Run(name, func(b *testing.B) {
			var (
				actual *http.Transport
				err    error
			)

			b.ReportAllocs()

			for b.Loop() {
				actual, err = rt.transportFor(tc.request)
			}

			if err != nil {
				b.Fatal(err)
			}

			if actual != tc.expected {
				b.Fatal("unexpected transport")
			}
		})
	}
}
