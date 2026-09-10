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

package bodyreadidle

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type responseWriter struct {
	*httptest.ResponseRecorder

	deadlines          []time.Time
	setReadDeadlineErr func(int) error
}

func (rw *responseWriter) SetReadDeadline(deadline time.Time) error {
	rw.deadlines = append(rw.deadlines, deadline)

	if rw.setReadDeadlineErr != nil {
		return rw.setReadDeadlineErr(len(rw.deadlines))
	}

	return nil
}

type bodyRecorder struct {
	io.Reader

	closed bool
	reads  int
}

func (b *bodyRecorder) Read(data []byte) (int, error) {
	b.reads++

	return b.Reader.Read(data)
}

func (b *bodyRecorder) Close() error {
	b.closed = true

	return nil
}

func TestNew(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		timeout time.Duration
		assert  func(t *testing.T, next, handler http.Handler)
	}{
		"disabled timeout returns next handler unchanged": {
			timeout: 0,
			assert: func(t *testing.T, next, handler http.Handler) {
				t.Helper()

				assert.Same(t, next, handler)
			},
		},
		"enabled timeout returns decorated handler": {
			timeout: time.Second,
			assert: func(t *testing.T, _, handler http.Handler) {
				t.Helper()

				assert.IsType(t, http.HandlerFunc(nil), handler)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			next := http.NewServeMux()

			// WHEN
			handler := New(tc.timeout)(next)

			// THEN
			tc.assert(t, next, handler)
		})
	}
}

func TestReadIdleBodyRead(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		body   io.ReadCloser
		rw     http.ResponseWriter
		assert func(t *testing.T, rw http.ResponseWriter, original, wrapped io.ReadCloser, read int, err error)
	}{
		"nil body is preserved": {
			rw: &responseWriter{ResponseRecorder: httptest.NewRecorder()},
			assert: func(t *testing.T, rw http.ResponseWriter, original, wrapped io.ReadCloser, read int, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Zero(t, read)
				assert.Nil(t, original)
				assert.Nil(t, wrapped)
				assert.Empty(t, rw.(*responseWriter).deadlines) //nolint:forcetypeassert
			},
		},
		"no body is preserved": {
			body: http.NoBody,
			rw:   &responseWriter{ResponseRecorder: httptest.NewRecorder()},
			assert: func(t *testing.T, rw http.ResponseWriter, original, wrapped io.ReadCloser, read int, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Zero(t, read)
				assert.Equal(t, original, wrapped)
				assert.Empty(t, rw.(*responseWriter).deadlines) //nolint:forcetypeassert
			},
		},
		"sets and clears deadline around read": {
			body: &bodyRecorder{Reader: strings.NewReader("test")},
			rw:   &responseWriter{ResponseRecorder: httptest.NewRecorder()},
			assert: func(t *testing.T, rw http.ResponseWriter, original, wrapped io.ReadCloser, read int, err error) {
				t.Helper()

				body := original.(*bodyRecorder) //nolint:forcetypeassert
				writer := rw.(*responseWriter)   //nolint:forcetypeassert

				require.NoError(t, err)
				assert.Equal(t, 1, read)
				assert.Equal(t, 1, body.reads)
				assert.NotSame(t, original, wrapped)
				require.Len(t, writer.deadlines, 2)
				assert.WithinDuration(t, time.Now().Add(time.Second), writer.deadlines[0], 100*time.Millisecond)
				assert.True(t, writer.deadlines[1].IsZero())
			},
		},
		"does not read body when setting deadline fails": {
			body: &bodyRecorder{Reader: strings.NewReader("test")},
			rw: &responseWriter{
				ResponseRecorder: httptest.NewRecorder(),
				setReadDeadlineErr: func(int) error {
					return assert.AnError
				},
			},
			assert: func(t *testing.T, rw http.ResponseWriter, original, _ io.ReadCloser, read int, err error) {
				t.Helper()

				body := original.(*bodyRecorder) //nolint:forcetypeassert
				writer := rw.(*responseWriter)   //nolint:forcetypeassert

				require.ErrorIs(t, err, assert.AnError)
				assert.Zero(t, read)
				assert.Zero(t, body.reads)
				require.Len(t, writer.deadlines, 1)
				assert.False(t, writer.deadlines[0].IsZero())
			},
		},
		"returns cleanup error after successful read": {
			body: &bodyRecorder{Reader: strings.NewReader("test")},
			rw: &responseWriter{
				ResponseRecorder: httptest.NewRecorder(),
				setReadDeadlineErr: func(call int) error {
					if call == 2 {
						return assert.AnError
					}

					return nil
				},
			},
			assert: func(t *testing.T, rw http.ResponseWriter, original, _ io.ReadCloser, read int, err error) {
				t.Helper()

				body := original.(*bodyRecorder) //nolint:forcetypeassert
				writer := rw.(*responseWriter)   //nolint:forcetypeassert

				require.ErrorIs(t, err, assert.AnError)
				assert.Equal(t, 1, read)
				assert.Equal(t, 1, body.reads)
				require.Len(t, writer.deadlines, 2)
				assert.True(t, writer.deadlines[1].IsZero())
			},
		},
		"preserves body read error": {
			body: &bodyRecorder{Reader: errorReader{err: io.ErrUnexpectedEOF}},
			rw: &responseWriter{
				ResponseRecorder: httptest.NewRecorder(),
				setReadDeadlineErr: func(call int) error {
					if call == 2 {
						return assert.AnError
					}

					return nil
				},
			},
			assert: func(t *testing.T, rw http.ResponseWriter, original, _ io.ReadCloser, read int, err error) {
				t.Helper()

				body := original.(*bodyRecorder) //nolint:forcetypeassert
				writer := rw.(*responseWriter)   //nolint:forcetypeassert

				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				require.NotErrorIs(t, err, assert.AnError)
				assert.Zero(t, read)
				assert.Equal(t, 1, body.reads)
				require.Len(t, writer.deadlines, 2)
				assert.True(t, writer.deadlines[1].IsZero())
			},
		},
		"fails if deadline control is not supported": {
			body: &bodyRecorder{Reader: strings.NewReader("test")},
			rw:   httptest.NewRecorder(),
			assert: func(t *testing.T, _ http.ResponseWriter, original, _ io.ReadCloser, read int, err error) {
				t.Helper()

				body := original.(*bodyRecorder) //nolint:forcetypeassert

				require.Error(t, err)
				require.ErrorIs(t, err, http.ErrNotSupported)
				assert.Zero(t, read)
				assert.Zero(t, body.reads)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			body := tc.body
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"http://heimdall.local/test",
				nil,
			)
			req.Body = body
			rw := tc.rw

			var (
				wrappedBody io.ReadCloser
				read        int
				err         error
			)

			handler := New(time.Second)(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				wrappedBody = req.Body
				if req.Body == nil || req.Body == http.NoBody {
					return
				}

				buffer := make([]byte, 1)
				read, err = req.Body.Read(buffer)
			}))

			// WHEN
			handler.ServeHTTP(rw, req)

			// THEN
			tc.assert(t, rw, body, wrappedBody, read, err)
		})
	}
}

func TestReadIdleBodyClose(t *testing.T) {
	t.Parallel()

	// GIVEN
	body := &bodyRecorder{Reader: strings.NewReader("test")}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://heimdall.local/test", nil)
	req.Body = body
	rw := &responseWriter{ResponseRecorder: httptest.NewRecorder()}

	var closeErr error
	handler := New(time.Second)(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		closeErr = req.Body.Close()
	}))

	// WHEN
	handler.ServeHTTP(rw, req)

	// THEN
	require.NoError(t, closeErr)
	assert.True(t, body.closed)
	assert.Empty(t, rw.deadlines)
}

func TestReadIdleBodyReadOverNetwork(t *testing.T) {
	for uc, tc := range map[string]struct {
		timeout       time.Duration
		contentLength string
		bodyParts     []string
		writeInterval time.Duration
		assert        func(t *testing.T, body string, err error, elapsed time.Duration)
	}{
		"blocked read times out": {
			timeout:       100 * time.Millisecond,
			contentLength: "1",
			assert: func(t *testing.T, _ string, err error, _ time.Duration) {
				t.Helper()

				require.Error(t, err)

				var netErr net.Error
				assert.True(t, errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout())
			},
		},
		"request longer than idle timeout succeeds with progress": {
			timeout:       200 * time.Millisecond,
			contentLength: "4",
			bodyParts:     []string{"1", "2", "3", "4"},
			writeInterval: 80 * time.Millisecond,
			assert: func(t *testing.T, body string, err error, elapsed time.Duration) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "1234", body)
				assert.Greater(t, elapsed, 200*time.Millisecond)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			result := make(chan struct {
				body string
				err  error
			}, 1)
			readStarted := make(chan struct{})
			server := httptest.NewServer(New(tc.timeout)(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				close(readStarted)

				body, err := io.ReadAll(req.Body)
				result <- struct {
					body string
					err  error
				}{body: string(body), err: err}
				rw.WriteHeader(http.StatusNoContent)
			})))
			defer server.Close()

			serverURL, err := url.Parse(server.URL)
			require.NoError(t, err)

			dialer := &net.Dialer{}
			conn, err := dialer.DialContext(t.Context(), "tcp", serverURL.Host)
			require.NoError(t, err)
			defer conn.Close()

			_, err = io.WriteString(
				conn,
				"POST / HTTP/1.1\r\nHost: "+serverURL.Host+"\r\nContent-Length: "+tc.contentLength+"\r\n\r\n",
			)
			require.NoError(t, err)

			select {
			case <-readStarted:
			case <-time.After(time.Second):
				require.FailNow(t, "request body read did not start")
			}

			started := time.Now()
			for idx, data := range tc.bodyParts {
				if idx > 0 {
					time.Sleep(tc.writeInterval)
				}

				_, err = io.WriteString(conn, data)
				require.NoError(t, err)
			}

			// WHEN
			var res struct {
				body string
				err  error
			}
			select {
			case res = <-result:
			case <-time.After(2 * time.Second):
				require.FailNow(t, "request body read did not complete")
			}

			// THEN
			tc.assert(t, res.body, res.err, time.Since(started))
		})
	}
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}
