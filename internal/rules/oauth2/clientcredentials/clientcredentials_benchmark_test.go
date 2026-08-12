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

package clientcredentials

import (
	"bytes"
	"net/http"
	"testing"
)

type clientCredentialsBenchmarkBody struct {
	*bytes.Reader
}

func (clientCredentialsBenchmarkBody) Close() error {
	return nil
}

func BenchmarkConfigApply(b *testing.B) {
	b.Run("basic auth", func(b *testing.B) {
		for _, tc := range []struct {
			name             string
			populatedHeaders bool
		}{
			{
				name: "empty headers",
			},
			{
				name:             "populated headers",
				populatedHeaders: true,
			},
		} {
			b.Run(tc.name, func(b *testing.B) {
				config := &Config{
					ClientID:     "client",
					ClientSecret: "secret",
				}

				base := newClientCredentialsBenchmarkRequest(b, tc.populatedHeaders)

				b.ReportAllocs()
				b.ResetTimer()

				for b.Loop() {
					req := *base

					if err := config.Apply(&req); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	})

	b.Run("request body", func(b *testing.B) {
		for _, tc := range []struct {
			name string
			form string
		}{
			{
				name: "minimal form",
				form: "grant_type=client_credentials",
			},
			{
				name: "populated form",
				form: "grant_type=client_credentials" +
					"&scope=read+write" +
					"&audience=https%3A%2F%2Fapi.example.com" +
					"&resource=orders",
			},
		} {
			b.Run(tc.name, func(b *testing.B) {
				config := &Config{
					ClientID:     "client",
					ClientSecret: "secret",
					AuthMethod:   AuthMethodRequestBody,
				}

				data := []byte(tc.form)
				reader := bytes.NewReader(data)
				body := &clientCredentialsBenchmarkBody{Reader: reader}

				base := newClientCredentialsBenchmarkRequest(b, true)

				b.ReportAllocs()
				b.ResetTimer()

				for b.Loop() {
					reader.Reset(data)

					req := *base
					req.Body = body
					req.ContentLength = int64(len(data))

					if err := config.Apply(&req); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	})
}

func newClientCredentialsBenchmarkRequest(
	b *testing.B,
	populatedHeaders bool,
) *http.Request {
	b.Helper()

	req, err := http.NewRequestWithContext(
		b.Context(),
		http.MethodPost,
		"https://issuer.example.com/token",
		nil,
	)
	if err != nil {
		b.Fatal(err)
	}

	if populatedHeaders {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
