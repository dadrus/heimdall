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
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type benchmarkResponseWriter struct {
	header http.Header
}

func (w *benchmarkResponseWriter) Header() http.Header          { return w.header }
func (*benchmarkResponseWriter) WriteHeader(_ int)              {}
func (*benchmarkResponseWriter) Write(data []byte) (int, error) { return len(data), nil }

type benchmarkUpstreamTarget struct {
	targetURL url.URL
}

func (t benchmarkUpstreamTarget) ApplyTo(targetURL *url.URL) { *targetURL = t.targetURL }
func (benchmarkUpstreamTarget) ForwardHostHeader() bool      { return false }

func BenchmarkProxyInvocation(b *testing.B) {
	req := httptest.NewRequestWithContext(
		b.Context(),
		http.MethodGet,
		"https://foo.bar/test",
		nil,
	)
	rc := &requestContext{}

	var result *proxyInvocation

	b.ReportAllocs()

	for b.Loop() {
		invocation := proxyInvocation{
			request: rc,
		}

		ctx := context.WithValue(
			req.Context(),
			proxyInvocationKey{},
			&invocation,
		)

		proxyReq := req.WithContext(ctx)
		result = proxyInvocationFrom(proxyReq.Context())
	}

	if result == nil || result.request != rc {
		b.Fatal("unexpected proxy invocation")
	}
}

func BenchmarkCommitterCommit(b *testing.B) {
	cf := newContextFactory()
	req := httptest.NewRequestWithContext(
		b.Context(),
		http.MethodGet,
		"https://foo.bar/test",
		nil,
	)
	ctx := cf.Create(req)
	ctx.PrepareUpstreamView(benchmarkUpstreamTarget{
		targetURL: url.URL{
			Scheme: "https",
			Host:   "upstream.example",
			Path:   "/target",
		},
	})

	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})

	committer := newCommitter(rt)
	rw := &benchmarkResponseWriter{
		header: make(http.Header),
	}

	if _, err := committer.Commit(rw, ctx); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := committer.Commit(rw, ctx); err != nil {
			b.Fatal(err)
		}
	}

	cf.Destroy(ctx)
}

func BenchmarkCommitterCommitWithResponseBody(b *testing.B) {
	responseBody := bytes.Repeat([]byte("a"), 128*1024)

	for _, tc := range []struct {
		name       string
		bufferPool bool
	}{
		{
			name:       "with buffer pool",
			bufferPool: true,
		},
		{
			name:       "without buffer pool",
			bufferPool: false,
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			cf := newContextFactory()
			req := httptest.NewRequestWithContext(
				b.Context(),
				http.MethodGet,
				"https://foo.bar/test",
				nil,
			)
			ctx := cf.Create(req)

			defer cf.Destroy(ctx)

			ctx.PrepareUpstreamView(benchmarkUpstreamTarget{
				targetURL: url.URL{
					Scheme: "https",
					Host:   "upstream.example",
					Path:   "/target",
				},
			})

			rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode:    http.StatusOK,
					Header:        make(http.Header),
					Body:          io.NopCloser(bytes.NewReader(responseBody)),
					ContentLength: int64(len(responseBody)),
					Request:       req,
				}, nil
			})

			committer := newCommitter(rt)
			if !tc.bufferPool {
				committer.proxy.BufferPool = nil
			}

			rw := &benchmarkResponseWriter{
				header: make(http.Header),
			}

			if _, err := committer.Commit(rw, ctx); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.SetBytes(int64(len(responseBody)))
			b.ResetTimer()

			for b.Loop() {
				if _, err := committer.Commit(rw, ctx); err != nil {
					b.Fatal(err)
				}
			}

			b.StopTimer()
		})
	}
}
