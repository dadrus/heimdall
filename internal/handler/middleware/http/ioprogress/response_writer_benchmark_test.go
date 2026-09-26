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
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type benchmarkWriter struct {
	header http.Header
}

func (w *benchmarkWriter) Header() http.Header            { return w.header }
func (*benchmarkWriter) WriteHeader(int)                  {}
func (*benchmarkWriter) SetWriteDeadline(time.Time) error { return nil }
func (*benchmarkWriter) Write(data []byte) (int, error)   { return len(data), nil }

type benchmarkHTTP1Writer struct {
	benchmarkWriter
}

func (*benchmarkHTTP1Writer) Flush()                                       {}
func (*benchmarkHTTP1Writer) Hijack() (net.Conn, *bufio.ReadWriter, error) { return nil, nil, nil }
func (*benchmarkHTTP1Writer) ReadFrom(src io.Reader) (int64, error)        { return io.Copy(io.Discard, src) }
func (*benchmarkHTTP1Writer) WriteString(data string) (int, error)         { return len(data), nil }
func (*benchmarkHTTP1Writer) CloseNotify() <-chan bool                     { return nil }

type benchmarkHTTP2Writer struct {
	benchmarkWriter
}

func (*benchmarkHTTP2Writer) Flush()                               {}
func (*benchmarkHTTP2Writer) Push(string, *http.PushOptions) error { return nil }
func (*benchmarkHTTP2Writer) WriteString(data string) (int, error) { return len(data), nil }
func (*benchmarkHTTP2Writer) CloseNotify() <-chan bool             { return nil }

func BenchmarkResponseWrite(b *testing.B) {
	smallPayload := bytes.Repeat([]byte("x"), 1024)
	largePayload := bytes.Repeat([]byte("x"), 256*1024)

	for name, tc := range map[string]struct {
		writeTimeout     time.Duration
		writeIdleTimeout time.Duration
		writeMinRate     int64
		payload          []byte
		http2            bool
		streamWrites     int
	}{
		"http1 disabled small": {
			payload: smallPayload,
		},
		"http1 hard timeout only": {
			writeTimeout: 30 * time.Second,
			payload:      smallPayload,
		},
		"http1 idle only small": {
			writeIdleTimeout: 30 * time.Second,
			payload:          smallPayload,
		},
		"http1 idle and minimum rate small": {
			writeIdleTimeout: 30 * time.Second,
			writeMinRate:     500,
			payload:          smallPayload,
		},
		"http1 idle only large chunked": {
			writeIdleTimeout: 30 * time.Second,
			payload:          largePayload,
		},
		"http1 idle and minimum rate large chunked": {
			writeIdleTimeout: 30 * time.Second,
			writeMinRate:     500,
			payload:          largePayload,
		},
		"http2 idle only small": {
			writeIdleTimeout: 30 * time.Second,
			payload:          smallPayload,
			http2:            true,
		},
		"http2 idle and minimum rate small": {
			writeIdleTimeout: 30 * time.Second,
			writeMinRate:     500,
			payload:          smallPayload,
			http2:            true,
		},
		"http1 streaming": {
			writeIdleTimeout: 30 * time.Second,
			writeMinRate:     500,
			payload:          smallPayload,
			streamWrites:     5,
		},
		"http2 streaming": {
			writeIdleTimeout: 30 * time.Second,
			writeMinRate:     500,
			payload:          smallPayload,
			http2:            true,
			streamWrites:     5,
		},
	} {
		b.Run(name, func(b *testing.B) {
			base := benchmarkWriter{header: make(http.Header)}
			var rw http.ResponseWriter
			if tc.http2 {
				rw = &benchmarkHTTP2Writer{benchmarkWriter: base}
			} else {
				rw = &benchmarkHTTP1Writer{benchmarkWriter: base}
			}

			req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/", nil)
			if tc.http2 {
				req.Proto = "HTTP/2.0"
				req.ProtoMajor = 2
				req.ProtoMinor = 0
			}
			handler := New(
				zerolog.Nop(),
				WithResponseWriteTimeout(tc.writeTimeout),
				WithResponseWriteIdleTimeout(tc.writeIdleTimeout),
				WithResponseWriteMinRate(tc.writeMinRate),
			)(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				writes := tc.streamWrites
				if writes == 0 {
					writes = 1
				}

				for range writes {
					if _, err := rw.Write(tc.payload); err != nil {
						b.Fatal(err)
					}
					if tc.streamWrites > 0 {
						http.NewResponseController(rw).Flush() //nolint:errcheck
					}
				}
			}))

			b.ReportAllocs()
			b.SetBytes(int64(len(tc.payload) * max(tc.streamWrites, 1)))
			b.ResetTimer()

			for b.Loop() {
				handler.ServeHTTP(rw, req)
			}
		})
	}
}

func BenchmarkResponseWriteDeadlineLifecycle(b *testing.B) {
	writer := &benchmarkWriter{header: make(http.Header)}

	for name, restoreAfterOperation := range map[string]bool{
		"arm only":        false,
		"arm and restore": true,
	} {
		b.Run(name, func(b *testing.B) {
			log := zerolog.Nop()
			state := &responseWriter{
				ResponseWriter: writer,
				deadlines:      newDeadlineTracker(0, 30*time.Second, 0, time.Now()),
				log:            &log,
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				state.armDeadline()
				if restoreAfterOperation {
					state.restoreDeadline()
				}
			}
		})
	}
}

func BenchmarkResponseReadFrom(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 256*1024)
	rw := &benchmarkHTTP1Writer{header: make(http.Header)}
	req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/", nil)
	src := bytes.NewReader(payload)
	handler := New(
		zerolog.Nop(),
		WithResponseWriteIdleTimeout(30*time.Second),
		WithResponseWriteMinRate(500),
	)(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			src.Reset(payload)
			if _, err := rw.(io.ReaderFrom).ReadFrom(src); err != nil { //nolint:forcetypeassert
				b.Fatal(err)
			}
		},
	))

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for b.Loop() {
		handler.ServeHTTP(rw, req)
	}
}
