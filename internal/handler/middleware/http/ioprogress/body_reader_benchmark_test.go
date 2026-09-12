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

package ioprogress

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type benchmarkReadWriter struct {
	header http.Header
}

func (w *benchmarkReadWriter) Header() http.Header             { return w.header }
func (*benchmarkReadWriter) WriteHeader(int)                   {}
func (*benchmarkReadWriter) Write(data []byte) (int, error)    { return len(data), nil }
func (*benchmarkReadWriter) SetReadDeadline(_ time.Time) error { return nil }

type benchmarkBody struct {
	bytes.Reader
}

func (*benchmarkBody) Close() error { return nil }

func BenchmarkRequestBodyRead(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 64*1024)

	for name, tc := range map[string]struct {
		readTimeout     time.Duration
		readIdleTimeout time.Duration
		readMinRate     int64
	}{
		"disabled": {},
		"idle only": {
			readIdleTimeout: 20 * time.Second,
		},
		"idle and minimum rate": {
			readIdleTimeout: 20 * time.Second,
			readMinRate:     500,
		},
	} {
		b.Run(name, func(b *testing.B) {
			writer := &benchmarkReadWriter{header: make(http.Header)}
			handler := New(
				zerolog.Nop(),
				WithRequestReadTimeout(tc.readTimeout),
				WithRequestBodyReadIdleTimeout(tc.readIdleTimeout),
				WithRequestBodyReadMinRate(tc.readMinRate),
			)(http.HandlerFunc(
				func(_ http.ResponseWriter, req *http.Request) {
					if _, err := io.Copy(io.Discard, req.Body); err != nil {
						b.Fatal(err)
					}
				},
			))

			body := new(benchmarkBody)
			req := httptest.NewRequestWithContext(
				b.Context(),
				http.MethodPost,
				"/",
				nil,
			)

			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()

			for b.Loop() {
				body.Reset(payload)
				req.Body = body

				handler.ServeHTTP(writer, req)
			}
		})
	}
}
