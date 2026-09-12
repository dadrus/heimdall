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
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"testing/iotest"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testHandler struct{}

func (*testHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

type plainResponseWriter struct {
	header http.Header
}

func (rw *plainResponseWriter) Header() http.Header {
	if rw.header == nil {
		rw.header = make(http.Header)
	}

	return rw.header
}

func (rw *plainResponseWriter) Write(data []byte) (int, error) { return len(data), nil }
func (rw *plainResponseWriter) WriteHeader(_ int)              {}

type deadlineConn struct {
	writeDeadlines   []time.Time
	writeDeadlineErr error
}

func (*deadlineConn) Read([]byte) (int, error)        { return 0, io.EOF }
func (*deadlineConn) Write(data []byte) (int, error)  { return len(data), nil }
func (*deadlineConn) Close() error                    { return nil }
func (*deadlineConn) LocalAddr() net.Addr             { return &net.TCPAddr{} }
func (*deadlineConn) RemoteAddr() net.Addr            { return &net.TCPAddr{} }
func (*deadlineConn) SetDeadline(time.Time) error     { return nil }
func (*deadlineConn) SetReadDeadline(time.Time) error { return nil }
func (con *deadlineConn) SetWriteDeadline(deadline time.Time) error {
	con.writeDeadlines = append(con.writeDeadlines, deadline)

	return con.writeDeadlineErr
}

type fullResponseWriter struct {
	plainResponseWriter

	deadlines       []time.Time
	writes          [][]byte
	writeStrings    []string
	writeHeaders    []int
	readFromSizes   []int
	flushes         int
	setDeadlineErr  func(time.Time) error
	writeSize       int
	writeErr        error
	writeStringSize int
	writeStringErr  error
	flushErr        error
	hijackErr       error
	hijackConn      net.Conn
	hijacks         int
	pushTarget      string
	pushOptions     *http.PushOptions
	pushErr         error
}

func (rw *fullResponseWriter) SetWriteDeadline(deadline time.Time) error {
	rw.deadlines = append(rw.deadlines, deadline)

	if rw.setDeadlineErr != nil {
		return rw.setDeadlineErr(deadline)
	}

	return nil
}

func (rw *fullResponseWriter) Write(data []byte) (int, error) {
	written := len(data)
	if rw.writeSize > 0 && written > rw.writeSize {
		written = rw.writeSize
	}

	rw.writes = append(rw.writes, append([]byte(nil), data[:written]...))

	return written, rw.writeErr
}

func (rw *fullResponseWriter) WriteString(data string) (int, error) {
	rw.writeStrings = append(rw.writeStrings, data)

	written := len(data)
	if rw.writeStringSize > 0 && written > rw.writeStringSize {
		written = rw.writeStringSize
	}

	return written, rw.writeStringErr
}

func (rw *fullResponseWriter) WriteHeader(code int) {
	rw.writeHeaders = append(rw.writeHeaders, code)
}

func (rw *fullResponseWriter) ReadFrom(src io.Reader) (int64, error) {
	data, err := io.ReadAll(src)
	if err != nil {
		return 0, err
	}

	rw.readFromSizes = append(rw.readFromSizes, len(data))

	return int64(len(data)), nil
}

func (rw *fullResponseWriter) Flush() { rw.flushes++ }

func (rw *fullResponseWriter) FlushError() error {
	rw.flushes++

	return rw.flushErr
}

func (rw *fullResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw.hijacks++

	return rw.hijackConn, nil, rw.hijackErr
}

func (rw *fullResponseWriter) Push(target string, opts *http.PushOptions) error {
	rw.pushTarget = target
	rw.pushOptions = opts

	return rw.pushErr
}

type flusherOnlyResponseWriter struct {
	plainResponseWriter

	flushes int
}

func (rw *flusherOnlyResponseWriter) Flush() { rw.flushes++ }

type flushErrorOnlyResponseWriter struct {
	plainResponseWriter

	flushes  int
	flushErr error
}

func (rw *flushErrorOnlyResponseWriter) FlushError() error {
	rw.flushes++

	return rw.flushErr
}

type http1ResponseWriter struct {
	plainResponseWriter
}

func (*http1ResponseWriter) Flush()                                       {}
func (*http1ResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) { return nil, nil, nil }
func (*http1ResponseWriter) ReadFrom(src io.Reader) (int64, error)        { return io.Copy(io.Discard, src) }
func (*http1ResponseWriter) WriteString(data string) (int, error)         { return len(data), nil }
func (*http1ResponseWriter) CloseNotify() <-chan bool                     { return nil }

type hijackerOnlyResponseWriter struct {
	plainResponseWriter
}

func (*hijackerOnlyResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}

type http2ResponseWriter struct {
	plainResponseWriter
}

func (*http2ResponseWriter) Flush()                               {}
func (*http2ResponseWriter) Push(string, *http.PushOptions) error { return nil }
func (*http2ResponseWriter) WriteString(data string) (int, error) { return len(data), nil }
func (*http2ResponseWriter) CloseNotify() <-chan bool             { return nil }

func TestNewWithoutProgressProtectionReturnsNextHandler(t *testing.T) {
	t.Parallel()

	for uc, writeTimeout := range map[string]time.Duration{
		"all policies disabled":                0,
		"hard timeout is owned by http server": time.Second,
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			next := &testHandler{}

			// WHEN
			handler := New(zerolog.Nop(), WithResponseWriteTimeout(writeTimeout))(next)

			// THEN
			assert.Same(t, next, handler)
		})
	}
}

func TestHandlerPreservesResponseWriterInterfaces(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		writer              http.ResponseWriter
		expectFlusher       bool
		expectHijacker      bool
		expectReaderFrom    bool
		expectPusher        bool
		expectStringWriter  bool
		expectCloseNotifier bool
	}{
		"plain writer remains plain": {
			writer: &plainResponseWriter{},
		},
		"flusher remains the only optional interface": {
			writer:        &flusherOnlyResponseWriter{},
			expectFlusher: true,
		},
		"uncommon interface combinations use the preserving fallback": {
			writer:         &hijackerOnlyResponseWriter{},
			expectHijacker: true,
		},
		"http1 style interfaces remain available": {
			writer:              &http1ResponseWriter{},
			expectFlusher:       true,
			expectHijacker:      true,
			expectReaderFrom:    true,
			expectStringWriter:  true,
			expectCloseNotifier: true,
		},
		"http2 style interfaces remain available": {
			writer:              &http2ResponseWriter{},
			expectFlusher:       true,
			expectPusher:        true,
			expectStringWriter:  true,
			expectCloseNotifier: true,
		},
		"optional interfaces remain available": {
			writer:             &fullResponseWriter{},
			expectFlusher:      true,
			expectHijacker:     true,
			expectReaderFrom:   true,
			expectPusher:       true,
			expectStringWriter: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			var handled bool
			handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
				func(rw http.ResponseWriter, _ *http.Request) {
					handled = true

					_, flusher := rw.(http.Flusher)
					_, hijacker := rw.(http.Hijacker)
					_, readerFrom := rw.(io.ReaderFrom)
					_, pusher := rw.(http.Pusher)
					_, stringWriter := rw.(io.StringWriter)
					_, closeNotifier := rw.(http.CloseNotifier) //nolint:staticcheck
					_, unwrapper := rw.(interface{ Unwrap() http.ResponseWriter })

					assert.Equal(t, tc.expectFlusher, flusher)
					assert.Equal(t, tc.expectHijacker, hijacker)
					assert.Equal(t, tc.expectReaderFrom, readerFrom)
					assert.Equal(t, tc.expectPusher, pusher)
					assert.Equal(t, tc.expectStringWriter, stringWriter)
					assert.Equal(t, tc.expectCloseNotifier, closeNotifier)
					assert.True(t, unwrapper)
				},
			))

			// WHEN
			handler.ServeHTTP(tc.writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

			// THEN
			assert.True(t, handled)
		})
	}
}

func TestHandlerProtectsWriteHeader(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		protoMajor int
	}{
		"http1 re-arms for final server flush": {
			protoMajor: 1,
		},
		"http2 re-arms for final stream flush": {
			protoMajor: 2,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			writer := &fullResponseWriter{}
			handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
				func(rw http.ResponseWriter, _ *http.Request) {
					rw.WriteHeader(http.StatusNoContent)
				},
			))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.ProtoMajor = tc.protoMajor

			// WHEN
			handler.ServeHTTP(writer, req)

			// THEN
			assert.Equal(t, []int{http.StatusNoContent}, writer.writeHeaders)
			require.Len(t, writer.deadlines, 3)
			assert.False(t, writer.deadlines[0].IsZero())
			assert.True(t, writer.deadlines[1].IsZero())
			assert.False(t, writer.deadlines[2].IsZero())
		})
	}
}

func TestHandlerProtectsEmptyWrite(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &fullResponseWriter{}
	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			written, err := rw.Write([]byte{})
			assert.NoError(t, err)
			assert.Zero(t, written)
		},
	))

	// WHEN
	handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	// THEN
	require.Len(t, writer.writes, 1)
	assert.Empty(t, writer.writes[0])
	require.Len(t, writer.deadlines, 3)
	assert.False(t, writer.deadlines[0].IsZero())
	assert.True(t, writer.deadlines[1].IsZero())
	assert.False(t, writer.deadlines[2].IsZero())
}

func TestHandlerPreservesShortWrite(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &fullResponseWriter{writeSize: 3}
	var written int
	var writeErr error
	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			written, writeErr = rw.Write([]byte("test"))
		},
	))

	// WHEN
	handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	// THEN
	assert.Equal(t, 3, written)
	require.ErrorIs(t, writeErr, io.ErrShortWrite)
	require.Len(t, writer.deadlines, 3)
	assert.True(t, writer.deadlines[1].IsZero())
	assert.False(t, writer.deadlines[2].IsZero())
}

func TestHandlerHandlesHijackWriteDeadlineOwnership(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		hijackErr             error
		connectionDeadlineErr error
		expectDeadlines       int
		expectConnectionClear bool
	}{
		"successful hijack ends response write policy": {
			expectDeadlines:       3,
			expectConnectionClear: true,
		},
		"failed hijack keeps response write policy": {
			hijackErr:       assert.AnError,
			expectDeadlines: 5,
		},
		"failed connection deadline clear does not fail successful hijack": {
			connectionDeadlineErr: assert.AnError,
			expectDeadlines:       3,
			expectConnectionClear: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			con := &deadlineConn{writeDeadlineErr: tc.connectionDeadlineErr}
			writer := &fullResponseWriter{
				hijackErr:  tc.hijackErr,
				hijackConn: con,
			}
			var hijackErr error
			handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
				func(rw http.ResponseWriter, _ *http.Request) {
					rw.WriteHeader(http.StatusSwitchingProtocols)
					_, _, hijackErr = rw.(http.Hijacker).Hijack() //nolint:forcetypeassert
				},
			))

			// WHEN
			handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

			// THEN
			require.ErrorIs(t, hijackErr, tc.hijackErr)
			assert.Equal(t, 1, writer.hijacks)
			require.Len(t, writer.deadlines, tc.expectDeadlines)
			assert.False(t, writer.deadlines[0].IsZero())
			assert.True(t, writer.deadlines[1].IsZero())
			assert.False(t, writer.deadlines[2].IsZero())

			if tc.expectConnectionClear {
				require.Len(t, con.writeDeadlines, 1)
				assert.True(t, con.writeDeadlines[0].IsZero())
			} else {
				assert.Empty(t, con.writeDeadlines)
				assert.True(t, writer.deadlines[3].IsZero())
				assert.False(t, writer.deadlines[4].IsZero())
			}
		})
	}
}

func TestHandlerChunksHTTP2WritesAndClearsDeadline(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &fullResponseWriter{}
	data := bytes.Repeat([]byte("x"), 2*defaultMaxWriteChunk+17)
	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			written, err := rw.Write(data)
			assert.NoError(t, err)
			assert.Equal(t, len(data), written)
		},
	))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	// WHEN
	handler.ServeHTTP(writer, req)

	// THEN
	require.Len(t, writer.writes, 3)
	assert.Len(t, writer.writes[0], defaultMaxWriteChunk)
	assert.Len(t, writer.writes[1], defaultMaxWriteChunk)
	assert.Len(t, writer.writes[2], 17)

	require.Len(t, writer.deadlines, 5)
	assert.False(t, writer.deadlines[0].IsZero())
	assert.False(t, writer.deadlines[1].IsZero())
	assert.False(t, writer.deadlines[2].IsZero())
	assert.True(t, writer.deadlines[3].IsZero())
	assert.False(t, writer.deadlines[4].IsZero())
}

func TestHandlerChunksHTTP2WriteString(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &fullResponseWriter{}
	data := string(bytes.Repeat([]byte("x"), 2*defaultMaxWriteChunk+17))
	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			written, err := rw.(io.StringWriter).WriteString(data) //nolint:forcetypeassert
			assert.NoError(t, err)
			assert.Equal(t, len(data), written)
		},
	))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	// WHEN
	handler.ServeHTTP(writer, req)

	// THEN
	require.Len(t, writer.writeStrings, 3)
	assert.Len(t, writer.writeStrings[0], defaultMaxWriteChunk)
	assert.Len(t, writer.writeStrings[1], defaultMaxWriteChunk)
	assert.Len(t, writer.writeStrings[2], 17)

	require.Len(t, writer.deadlines, 5)
	assert.True(t, writer.deadlines[3].IsZero())
	assert.False(t, writer.deadlines[4].IsZero())
}

func TestHandlerHandlesWriteStringResults(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		data      string
		writeSize int
		writeErr  error
		expectN   int
		expectErr error
	}{
		"empty string": {},
		"write error": {
			data:      "test",
			writeSize: 3,
			writeErr:  assert.AnError,
			expectN:   3,
			expectErr: assert.AnError,
		},
		"short write": {
			data:      "test",
			writeSize: 3,
			expectN:   3,
			expectErr: io.ErrShortWrite,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			writer := &fullResponseWriter{
				writeStringSize: tc.writeSize,
				writeStringErr:  tc.writeErr,
			}
			var written int
			var writeErr error
			handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
				func(rw http.ResponseWriter, _ *http.Request) {
					written, writeErr = rw.(io.StringWriter).WriteString(tc.data) //nolint:forcetypeassert
				},
			))

			// WHEN
			handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

			// THEN
			assert.Equal(t, tc.expectN, written)
			require.ErrorIs(t, writeErr, tc.expectErr)
			require.Len(t, writer.deadlines, 3)
			assert.True(t, writer.deadlines[1].IsZero())
			assert.False(t, writer.deadlines[2].IsZero())
		})
	}
}

func TestHandlerChunksHTTP2ReadFrom(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &fullResponseWriter{}
	data := bytes.Repeat([]byte("x"), 2*defaultMaxWriteChunk+17)
	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			read, err := rw.(io.ReaderFrom).ReadFrom(bytes.NewReader(data)) //nolint:forcetypeassert
			assert.NoError(t, err)
			assert.Equal(t, int64(len(data)), read)
		},
	))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	// WHEN
	handler.ServeHTTP(writer, req)

	// THEN
	assert.Equal(t, []int{defaultMaxWriteChunk, defaultMaxWriteChunk, 17}, writer.readFromSizes)
	require.Len(t, writer.deadlines, 5)
	assert.True(t, writer.deadlines[3].IsZero())
	assert.False(t, writer.deadlines[4].IsZero())
}

func TestHandlerPreservesReadFromError(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &fullResponseWriter{}
	var read int64
	var readErr error
	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			read, readErr = rw.(io.ReaderFrom).ReadFrom(iotest.ErrReader(assert.AnError)) //nolint:forcetypeassert
		},
	))

	// WHEN
	handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	// THEN
	assert.Zero(t, read)
	require.ErrorIs(t, readErr, assert.AnError)
	require.Len(t, writer.deadlines, 3)
	assert.False(t, writer.deadlines[0].IsZero())
	assert.True(t, writer.deadlines[1].IsZero())
	assert.False(t, writer.deadlines[2].IsZero())
}

func TestHandlerFailsOpenIfDeadlineCannotBeSet(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &fullResponseWriter{
		setDeadlineErr: func(time.Time) error { return assert.AnError },
	}
	data := bytes.Repeat([]byte("x"), defaultMaxWriteChunk+17)
	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			written, err := rw.Write(data)
			assert.NoError(t, err)
			assert.Equal(t, len(data), written)
		},
	))

	// WHEN
	handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	// THEN
	assert.Len(t, writer.writes, 2)
	assert.Len(t, writer.deadlines, 1)
	assert.False(t, writer.deadlines[0].IsZero())
}

func TestHandlerDoesNotReplaceWriteResultWithDeadlineCleanupError(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &fullResponseWriter{
		setDeadlineErr: func(deadline time.Time) error {
			if deadline.IsZero() {
				return assert.AnError
			}

			return nil
		},
	}
	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			written, err := rw.Write([]byte("test"))
			assert.NoError(t, err)
			assert.Equal(t, 4, written)
		},
	))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	// WHEN
	handler.ServeHTTP(writer, req)

	// THEN
	require.Len(t, writer.deadlines, 3)
	assert.True(t, writer.deadlines[1].IsZero())
	assert.False(t, writer.deadlines[2].IsZero())
}

func TestHandlerPreservesWriteError(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &fullResponseWriter{
		writeSize: 3,
		writeErr:  assert.AnError,
	}
	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			written, err := rw.Write([]byte("test"))
			assert.ErrorIs(t, err, assert.AnError)
			assert.Equal(t, 3, written)
		},
	))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	// WHEN
	handler.ServeHTTP(writer, req)

	// THEN
	require.Len(t, writer.deadlines, 3)
	assert.True(t, writer.deadlines[1].IsZero())
	assert.False(t, writer.deadlines[2].IsZero())
}

func TestHandlerProtectsFlushOperations(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		flush func(t *testing.T, rw http.ResponseWriter)
	}{
		"flush": {
			flush: func(t *testing.T, rw http.ResponseWriter) {
				t.Helper()
				rw.(http.Flusher).Flush() //nolint:forcetypeassert
			},
		},
		"flush error": {
			flush: func(t *testing.T, rw http.ResponseWriter) {
				t.Helper()
				err := rw.(interface{ FlushError() error }).FlushError() //nolint:forcetypeassert
				require.ErrorIs(t, err, assert.AnError)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			writer := &fullResponseWriter{flushErr: assert.AnError}
			handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
				func(rw http.ResponseWriter, _ *http.Request) {
					tc.flush(t, rw)
				},
			))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.Proto = "HTTP/2.0"
			req.ProtoMajor = 2
			req.ProtoMinor = 0

			// WHEN
			handler.ServeHTTP(writer, req)

			// THEN
			assert.Equal(t, 1, writer.flushes)
			require.Len(t, writer.deadlines, 3)
			assert.False(t, writer.deadlines[0].IsZero())
			assert.True(t, writer.deadlines[1].IsZero())
			assert.False(t, writer.deadlines[2].IsZero())
		})
	}
}

func TestHandlerBridgesFlushInterfaces(t *testing.T) {
	t.Parallel()

	t.Run("Flush uses FlushError", func(t *testing.T) {
		t.Parallel()

		// GIVEN
		writer := &flushErrorOnlyResponseWriter{flushErr: assert.AnError}
		handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
			func(rw http.ResponseWriter, _ *http.Request) {
				rw.(http.Flusher).Flush() //nolint:forcetypeassert
			},
		))

		// WHEN
		handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

		// THEN
		assert.Equal(t, 1, writer.flushes)
	})

	t.Run("FlushError uses Flush", func(t *testing.T) {
		t.Parallel()

		// GIVEN
		writer := &flusherOnlyResponseWriter{}
		handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
			func(rw http.ResponseWriter, _ *http.Request) {
				err := rw.(flushErrorWriter).FlushError() //nolint:forcetypeassert
				assert.NoError(t, err)
			},
		))

		// WHEN
		handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

		// THEN
		assert.Equal(t, 1, writer.flushes)
	})
}

func TestHandlerForwardsPush(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &fullResponseWriter{pushErr: assert.AnError}
	options := &http.PushOptions{Method: http.MethodGet}
	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			err := rw.(http.Pusher).Push("/asset", options) //nolint:forcetypeassert
			assert.ErrorIs(t, err, assert.AnError)
		},
	))

	// WHEN
	handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	// THEN
	assert.Equal(t, "/asset", writer.pushTarget)
	assert.Same(t, options, writer.pushOptions)
}

func TestHandlerClearsHTTP2IdleDeadlineBetweenWrites(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &fullResponseWriter{}
	idleTimeout := 20 * time.Millisecond
	var secondWriteStartedAt time.Time
	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(idleTimeout))(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			_, err := rw.Write([]byte("first"))
			assert.NoError(t, err)

			time.Sleep(3 * idleTimeout)
			secondWriteStartedAt = time.Now()

			_, err = rw.Write([]byte("second"))
			assert.NoError(t, err)
		},
	))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	// WHEN
	handler.ServeHTTP(writer, req)

	// THEN
	require.Len(t, writer.deadlines, 5)
	assert.True(t, writer.deadlines[1].IsZero())
	assert.WithinDuration(t, secondWriteStartedAt.Add(idleTimeout), writer.deadlines[2], 10*time.Millisecond)
	assert.True(t, writer.deadlines[3].IsZero())
	assert.False(t, writer.deadlines[4].IsZero())
}

func TestHandlerRearmsHTTP1IdleDeadlineAfterApplicationPause(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &fullResponseWriter{}
	idleTimeout := 20 * time.Millisecond
	var secondWriteStartedAt time.Time
	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(idleTimeout))(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			_, err := rw.Write([]byte("first"))
			assert.NoError(t, err)

			time.Sleep(3 * idleTimeout)
			secondWriteStartedAt = time.Now()

			_, err = rw.Write([]byte("second"))
			assert.NoError(t, err)
		},
	))

	// WHEN
	handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	// THEN
	require.Len(t, writer.deadlines, 5)
	assert.False(t, writer.deadlines[0].IsZero())
	assert.True(t, writer.deadlines[1].IsZero())
	assert.WithinDuration(t, secondWriteStartedAt.Add(idleTimeout), writer.deadlines[2], 10*time.Millisecond)
	assert.True(t, writer.deadlines[3].IsZero())
	assert.False(t, writer.deadlines[4].IsZero())
}

func TestHandlerRearmsDeadlineForFinalServerFlush(t *testing.T) {
	t.Parallel()

	for uc, protoMajor := range map[string]int{
		"http1": 1,
		"http2": 2,
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			writer := &fullResponseWriter{}
			handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(time.Second))(http.HandlerFunc(
				func(rw http.ResponseWriter, _ *http.Request) {
					written, err := rw.Write([]byte("buffered response"))
					assert.NoError(t, err)
					assert.Equal(t, len("buffered response"), written)
				},
			))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.ProtoMajor = protoMajor

			// WHEN
			handler.ServeHTTP(writer, req)

			// THEN
			require.Len(t, writer.deadlines, 3)
			assert.False(t, writer.deadlines[0].IsZero())
			assert.True(t, writer.deadlines[1].IsZero())
			assert.False(t, writer.deadlines[2].IsZero())
		})
	}
}

func TestHandlerCapsProgressDeadlineWithHardWriteTimeout(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &fullResponseWriter{}
	hardTimeout := 20 * time.Millisecond
	var writeStartedAt time.Time
	handler := New(
		zerolog.Nop(),
		WithResponseWriteTimeout(hardTimeout),
		WithResponseWriteIdleTimeout(time.Second),
	)(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			time.Sleep(3 * hardTimeout)
			writeStartedAt = time.Now()

			_, err := rw.Write([]byte("test"))
			assert.NoError(t, err)
		},
	))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	// WHEN
	handler.ServeHTTP(writer, req)

	// THEN
	require.Len(t, writer.deadlines, 3)
	assert.True(t, writer.deadlines[0].Before(writeStartedAt))
	assert.Equal(t, writer.deadlines[0], writer.deadlines[1])
	assert.True(t, writer.deadlines[2].Before(writeStartedAt))
}

func TestServerWriteTimeoutRemainsAbsoluteWithProgress(t *testing.T) {
	const (
		hardTimeout = 200 * time.Millisecond
		idleTimeout = 500 * time.Millisecond
		chunkDelay  = 50 * time.Millisecond
		chunkCount  = 8
	)

	handler := New(
		zerolog.Nop(),
		WithResponseWriteTimeout(hardTimeout),
		WithResponseWriteIdleTimeout(idleTimeout),
	)(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			for range chunkCount {
				if _, err := rw.Write([]byte("chunk\n")); err != nil {
					return
				}

				if err := http.NewResponseController(rw).Flush(); err != nil {
					return
				}

				time.Sleep(chunkDelay)
			}
		},
	))

	server := httptest.NewUnstartedServer(handler)
	server.Config.WriteTimeout = hardTimeout
	server.Start()
	t.Cleanup(server.Close)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	response, err := server.Client().Do(request)
	require.NoError(t, err)
	defer response.Body.Close()

	body, readErr := io.ReadAll(response.Body)
	assert.True(t, readErr != nil || len(body) < chunkCount*len("chunk\n"))
}

func TestHTTP2SilentStreamDoesNotBlockParallelStream(t *testing.T) {
	// GIVEN
	const writeIdleTimeout = 50 * time.Millisecond

	firstWriteDone := make(chan struct{})
	continueSlowStream := make(chan struct{})
	remoteAddresses := make(chan string, 2)

	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(writeIdleTimeout))(http.HandlerFunc(
		func(rw http.ResponseWriter, req *http.Request) {
			remoteAddresses <- req.RemoteAddr

			switch req.URL.Path {
			case "/slow":
				if _, err := rw.Write([]byte("first\n")); err != nil {
					return
				}
				if err := http.NewResponseController(rw).Flush(); err != nil {
					return
				}
				close(firstWriteDone)

				<-continueSlowStream

				_, _ = rw.Write([]byte("second\n"))
			case "/fast":
				_, _ = rw.Write([]byte("fast\n"))
			default:
				http.NotFound(rw, req)
			}
		},
	))

	server := httptest.NewUnstartedServer(handler)
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetHTTP1(true)
	server.Config.Protocols.SetHTTP2(true)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}} //nolint:gosec
	server.StartTLS()
	defer server.Close()

	transport := server.Client().Transport.(*http.Transport).Clone() //nolint:forcetypeassert
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP2(true)
	client := &http.Client{Transport: transport}

	slowResponse := make(chan *http.Response, 1)
	slowError := make(chan error, 1)

	go func() {
		response, err := client.Get(server.URL + "/slow") //nolint:bodyclose,noctx
		if err != nil {
			slowError <- err

			return
		}

		slowResponse <- response
	}()

	select {
	case <-firstWriteDone:
	case <-time.After(time.Second):
		t.Fatal("slow stream did not produce its first write")
	}

	// WHEN
	fastResponse, err := client.Get(server.URL + "/fast") //nolint:noctx

	// THEN
	require.NoError(t, err)
	fastBody, err := io.ReadAll(fastResponse.Body)
	require.NoError(t, err)
	require.NoError(t, fastResponse.Body.Close())
	assert.Equal(t, "HTTP/2.0", fastResponse.Proto)
	assert.Equal(t, "fast\n", string(fastBody))

	// Keep the first stream silent longer than the write-idle timeout. Since no
	// write is in flight, this must not consume its write-idle budget.
	time.Sleep(3 * writeIdleTimeout)
	close(continueSlowStream)

	select {
	case err := <-slowError:
		require.NoError(t, err)
	case response := <-slowResponse:
		defer response.Body.Close()

		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		assert.Equal(t, "HTTP/2.0", response.Proto)
		assert.Equal(t, "first\nsecond\n", string(body))
	case <-time.After(time.Second):
		t.Fatal("slow stream did not complete")
	}

	firstRemoteAddress := <-remoteAddresses
	secondRemoteAddress := <-remoteAddresses
	assert.Equal(t, firstRemoteAddress, secondRemoteAddress, "expected both streams on the same HTTP/2 connection")
}

func TestHTTP2HardWriteDeadlineRemainsArmedBetweenOperations(t *testing.T) {
	// GIVEN
	const (
		hardTimeout      = 200 * time.Millisecond
		writeIdleTimeout = 50 * time.Millisecond
	)

	firstWriteDone := make(chan struct{})
	releaseHandler := make(chan struct{})

	handler := New(
		zerolog.Nop(),
		WithResponseWriteTimeout(hardTimeout),
		WithResponseWriteIdleTimeout(writeIdleTimeout),
	)(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			if _, err := rw.Write([]byte("first\n")); err != nil {
				return
			}
			if err := http.NewResponseController(rw).Flush(); err != nil {
				return
			}
			close(firstWriteDone)

			<-releaseHandler
		},
	))

	server := httptest.NewUnstartedServer(handler)
	server.Config.WriteTimeout = hardTimeout
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetHTTP1(true)
	server.Config.Protocols.SetHTTP2(true)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}} //nolint:gosec
	server.StartTLS()
	defer func() {
		close(releaseHandler)
		server.Close()
	}()

	transport := server.Client().Transport.(*http.Transport).Clone() //nolint:forcetypeassert
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP2(true)
	client := &http.Client{Transport: transport}

	response, err := client.Get(server.URL) //nolint:bodyclose,noctx
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, "HTTP/2.0", response.Proto)

	select {
	case <-firstWriteDone:
	case <-time.After(time.Second):
		t.Fatal("HTTP/2 stream did not produce its first write")
	}

	type readResult struct {
		body string
		err  error
	}

	result := make(chan readResult, 1)
	go func() {
		body, readErr := io.ReadAll(response.Body)
		result <- readResult{body: string(body), err: readErr}
	}()

	// WHEN
	// The handler performs no further I/O. The absolute write deadline must stay
	// armed while the operation-specific idle deadline is removed.
	select {
	case res := <-result:
		// THEN
		assert.Equal(t, "first\n", res.body)
		require.Error(t, res.err)
	case <-time.After(time.Second):
		t.Fatal("HTTP/2 stream did not hit the hard write deadline while the handler was idle")
	}
}

type rateResponseWriter struct {
	plainResponseWriter

	currentDeadline time.Time
	delays          []time.Duration
	writeSize       int
	writes          int
}

func (rw *rateResponseWriter) SetWriteDeadline(deadline time.Time) error {
	rw.currentDeadline = deadline

	return nil
}

func (rw *rateResponseWriter) Write(data []byte) (int, error) {
	if rw.writes < len(rw.delays) {
		time.Sleep(rw.delays[rw.writes])
	}

	if !rw.currentDeadline.IsZero() && !rw.currentDeadline.After(time.Now()) {
		return 0, os.ErrDeadlineExceeded
	}

	rw.writes++
	if rw.writeSize > 0 && len(data) > rw.writeSize {
		return rw.writeSize, nil
	}

	return len(data), nil
}

func TestHandlerMinimumRateCountsApplicationPause(t *testing.T) {
	t.Parallel()

	// GIVEN
	writer := &rateResponseWriter{}
	idleTimeout := 50 * time.Millisecond
	var writeErr error
	handler := New(
		zerolog.Nop(),
		WithResponseWriteIdleTimeout(idleTimeout),
		WithResponseWriteMinRate(100),
	)(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			if _, err := rw.Write([]byte("a")); err != nil {
				writeErr = err

				return
			}

			time.Sleep(2 * idleTimeout)
			_, writeErr = rw.Write([]byte("b"))
		},
	))

	// WHEN
	handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	// THEN
	require.ErrorIs(t, writeErr, os.ErrDeadlineExceeded)
	assert.Equal(t, 1, writer.writes)
}

func TestHandlerMinimumRateRejectsTricklingButAllowsSufficientProgress(t *testing.T) {
	for uc, tc := range map[string]struct {
		delays        []time.Duration
		writes        [][]byte
		expectTimeout bool
	}{
		"trickle below minimum rate": {
			delays:        []time.Duration{50 * time.Millisecond, 80 * time.Millisecond},
			writes:        [][]byte{{'a'}, {'b'}},
			expectTimeout: true,
		},
		"progress above minimum rate": {
			delays: []time.Duration{50 * time.Millisecond, 50 * time.Millisecond},
			writes: [][]byte{
				bytes.Repeat([]byte{'a'}, 100),
				bytes.Repeat([]byte{'b'}, 100),
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			writer := &rateResponseWriter{delays: tc.delays}
			var writeErr error
			handler := New(
				zerolog.Nop(),
				WithResponseWriteIdleTimeout(100*time.Millisecond),
				WithResponseWriteMinRate(500),
			)(http.HandlerFunc(
				func(rw http.ResponseWriter, _ *http.Request) {
					for _, data := range tc.writes {
						if _, err := rw.Write(data); err != nil {
							writeErr = err

							return
						}
					}
				},
			))

			// WHEN
			handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

			// THEN
			if tc.expectTimeout {
				require.ErrorIs(t, writeErr, os.ErrDeadlineExceeded)
				assert.Equal(t, 1, writer.writes)
			} else {
				require.NoError(t, writeErr)
				assert.Equal(t, len(tc.writes), writer.writes)
			}
		})
	}
}

type singleConnListener struct {
	conn     net.Conn
	closed   chan struct{}
	accepted bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true

		return l.conn, nil
	}

	<-l.closed

	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}

	return l.conn.Close()
}

func (*singleConnListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestHTTP1BlockedClientReadTimesOutActiveResponseWrite(t *testing.T) {
	// GIVEN
	serverConn, clientConn := net.Pipe()
	listener := &singleConnListener{
		conn:   serverConn,
		closed: make(chan struct{}),
	}
	defer listener.Close()
	defer clientConn.Close()

	writeResult := make(chan error, 1)
	handler := New(zerolog.Nop(), WithResponseWriteIdleTimeout(75*time.Millisecond))(http.HandlerFunc(
		func(rw http.ResponseWriter, _ *http.Request) {
			_, err := rw.Write(bytes.Repeat([]byte("x"), 2*defaultMaxWriteChunk))
			writeResult <- err
		},
	))
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: time.Second,
	}
	defer server.Close()

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()

	_, err := io.WriteString(clientConn, "GET / HTTP/1.1\r\nHost: heimdall.local\r\n\r\n")
	require.NoError(t, err)

	// WHEN / THEN
	select {
	case err := <-writeResult:
		require.Error(t, err)

		var netErr net.Error
		assert.True(t, errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout())
	case <-time.After(time.Second):
		t.Fatal("blocked response write did not time out")
	}
}
