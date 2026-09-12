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

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type readDeadlineWriter struct {
	*httptest.ResponseRecorder

	deadlines          []time.Time
	setReadDeadlineErr func(int) error
}

func (rw *readDeadlineWriter) SetReadDeadline(deadline time.Time) error {
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
		readTimeout     time.Duration
		readIdleTimeout time.Duration
		readMinRate     int64
		assert          func(t *testing.T, next, handler http.Handler)
	}{
		"disabled policies return next handler unchanged": {
			assert: func(t *testing.T, next, handler http.Handler) {
				t.Helper()

				assert.Same(t, next, handler)
			},
		},
		"hard timeout is owned by http server": {
			readTimeout: time.Second,
			assert: func(t *testing.T, next, handler http.Handler) {
				t.Helper()

				assert.Same(t, next, handler)
			},
		},
		"idle timeout returns decorated handler": {
			readIdleTimeout: time.Second,
			assert: func(t *testing.T, _, handler http.Handler) {
				t.Helper()

				assert.IsType(t, http.HandlerFunc(nil), handler)
			},
		},
		"minimum rate with idle timeout returns decorated handler": {
			readIdleTimeout: time.Second,
			readMinRate:     1,
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
			handler := New(
				zerolog.Nop(),
				WithRequestReadTimeout(tc.readTimeout),
				WithRequestBodyReadIdleTimeout(tc.readIdleTimeout),
				WithRequestBodyReadMinRate(tc.readMinRate),
			)(next)

			// THEN
			tc.assert(t, next, handler)
		})
	}
}

func TestBodyReadCloserRead(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		body   io.ReadCloser
		rw     http.ResponseWriter
		assert func(t *testing.T, rw http.ResponseWriter, original, wrapped io.ReadCloser, read int, err error)
	}{
		"nil body is preserved": {
			rw: &readDeadlineWriter{ResponseRecorder: httptest.NewRecorder()},
			assert: func(t *testing.T, rw http.ResponseWriter, original, wrapped io.ReadCloser, read int, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Zero(t, read)
				assert.Nil(t, original)
				assert.Nil(t, wrapped)
				assert.Empty(t, rw.(*readDeadlineWriter).deadlines) //nolint:forcetypeassert
			},
		},
		"no body is preserved": {
			body: http.NoBody,
			rw:   &readDeadlineWriter{ResponseRecorder: httptest.NewRecorder()},
			assert: func(t *testing.T, rw http.ResponseWriter, original, wrapped io.ReadCloser, read int, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Zero(t, read)
				assert.Equal(t, original, wrapped)
				assert.Empty(t, rw.(*readDeadlineWriter).deadlines) //nolint:forcetypeassert
			},
		},
		"sets and clears deadline around read": {
			body: &bodyRecorder{Reader: strings.NewReader("test")},
			rw:   &readDeadlineWriter{ResponseRecorder: httptest.NewRecorder()},
			assert: func(t *testing.T, rw http.ResponseWriter, original, wrapped io.ReadCloser, read int, err error) {
				t.Helper()

				body := original.(*bodyRecorder)   //nolint:forcetypeassert
				writer := rw.(*readDeadlineWriter) //nolint:forcetypeassert

				require.NoError(t, err)
				assert.Equal(t, 1, read)
				assert.Equal(t, 1, body.reads)
				assert.NotSame(t, original, wrapped)
				require.Len(t, writer.deadlines, 2)
				assert.WithinDuration(t, time.Now().Add(time.Second), writer.deadlines[0], 100*time.Millisecond)
				assert.True(t, writer.deadlines[1].IsZero())
			},
		},
		"reads body when setting deadline fails": {
			body: &bodyRecorder{Reader: strings.NewReader("test")},
			rw: &readDeadlineWriter{
				ResponseRecorder: httptest.NewRecorder(),
				setReadDeadlineErr: func(int) error {
					return assert.AnError
				},
			},
			assert: func(t *testing.T, rw http.ResponseWriter, original, _ io.ReadCloser, read int, err error) {
				t.Helper()

				body := original.(*bodyRecorder)   //nolint:forcetypeassert
				writer := rw.(*readDeadlineWriter) //nolint:forcetypeassert

				require.NoError(t, err)
				assert.Equal(t, 1, read)
				assert.Equal(t, 1, body.reads)
				require.Len(t, writer.deadlines, 1)
				assert.False(t, writer.deadlines[0].IsZero())
			},
		},
		"does not replace successful read with cleanup error": {
			body: &bodyRecorder{Reader: strings.NewReader("test")},
			rw: &readDeadlineWriter{
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

				body := original.(*bodyRecorder)   //nolint:forcetypeassert
				writer := rw.(*readDeadlineWriter) //nolint:forcetypeassert

				require.NoError(t, err)
				assert.Equal(t, 1, read)
				assert.Equal(t, 1, body.reads)
				require.Len(t, writer.deadlines, 2)
				assert.True(t, writer.deadlines[1].IsZero())
			},
		},
		"preserves body read error": {
			body: &bodyRecorder{Reader: errorReader{err: io.ErrUnexpectedEOF}},
			rw: &readDeadlineWriter{
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

				body := original.(*bodyRecorder)   //nolint:forcetypeassert
				writer := rw.(*readDeadlineWriter) //nolint:forcetypeassert

				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				require.NotErrorIs(t, err, assert.AnError)
				assert.Zero(t, read)
				assert.Equal(t, 1, body.reads)
				require.Len(t, writer.deadlines, 2)
				assert.True(t, writer.deadlines[1].IsZero())
			},
		},
		"reads body if deadline control is not supported": {
			body: &bodyRecorder{Reader: strings.NewReader("test")},
			rw:   httptest.NewRecorder(),
			assert: func(t *testing.T, _ http.ResponseWriter, original, _ io.ReadCloser, read int, err error) {
				t.Helper()

				body := original.(*bodyRecorder) //nolint:forcetypeassert

				require.NoError(t, err)
				assert.Equal(t, 1, read)
				assert.Equal(t, 1, body.reads)
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

			handler := New(zerolog.Nop(), WithRequestBodyReadIdleTimeout(time.Second))(http.HandlerFunc(
				func(_ http.ResponseWriter, req *http.Request) {
					wrappedBody = req.Body
					if req.Body == nil || req.Body == http.NoBody {
						return
					}

					buffer := make([]byte, 1)
					read, err = req.Body.Read(buffer)
				},
			))

			// WHEN
			handler.ServeHTTP(rw, req)

			// THEN
			tc.assert(t, rw, body, wrappedBody, read, err)
		})
	}
}

func TestBodyReadCloserRestoresHardDeadlineAfterRead(t *testing.T) {
	t.Parallel()

	// GIVEN
	body := &bodyRecorder{Reader: strings.NewReader("test")}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://heimdall.local/test", nil)
	req.Body = body
	rw := &readDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	handler := New(
		zerolog.Nop(),
		WithRequestReadTimeout(time.Second),
		WithRequestBodyReadIdleTimeout(2*time.Second),
	)(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		buffer := make([]byte, 1)
		_, err := req.Body.Read(buffer)
		require.NoError(t, err)
	}))

	// WHEN
	handler.ServeHTTP(rw, req)

	// THEN
	require.Len(t, rw.deadlines, 2)
	assert.False(t, rw.deadlines[0].IsZero())
	assert.Equal(t, rw.deadlines[0], rw.deadlines[1])
}

func TestBodyReadCloserClose(t *testing.T) {
	t.Parallel()

	// GIVEN
	body := &bodyRecorder{Reader: strings.NewReader("test")}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://heimdall.local/test", nil)
	req.Body = body
	rw := &readDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}

	var closeErr error
	handler := New(zerolog.Nop(), WithRequestBodyReadIdleTimeout(time.Second))(http.HandlerFunc(
		func(_ http.ResponseWriter, req *http.Request) {
			closeErr = req.Body.Close()
		},
	))

	// WHEN
	handler.ServeHTTP(rw, req)

	// THEN
	require.NoError(t, closeErr)
	assert.True(t, body.closed)
	assert.Empty(t, rw.deadlines)
}

func TestReadHardTimeoutOnlyDoesNotWrapBody(t *testing.T) {
	t.Parallel()

	// GIVEN
	body := &bodyRecorder{Reader: strings.NewReader("test")}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://heimdall.local/test", nil)
	req.Body = body
	rw := &readDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}

	var wrapped io.ReadCloser
	handler := New(zerolog.Nop(), WithRequestReadTimeout(time.Second))(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		wrapped = req.Body
	}))

	// WHEN
	handler.ServeHTTP(rw, req)

	// THEN
	assert.Same(t, body, wrapped)
	assert.Empty(t, rw.deadlines)
}

func TestReadMinimumRateCountsApplicationPause(t *testing.T) {
	t.Parallel()

	// GIVEN
	body := &bodyRecorder{Reader: strings.NewReader("ab")}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://heimdall.local/test", nil)
	req.Body = body
	rw := &readDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}

	var secondReadStartedAt time.Time
	handler := New(
		zerolog.Nop(),
		WithRequestBodyReadIdleTimeout(50*time.Millisecond),
		WithRequestBodyReadMinRate(100),
	)(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		buffer := make([]byte, 1)
		_, firstErr := req.Body.Read(buffer)
		require.NoError(t, firstErr)

		time.Sleep(100 * time.Millisecond)
		secondReadStartedAt = time.Now()
		_, _ = req.Body.Read(buffer)
	}))

	// WHEN
	handler.ServeHTTP(rw, req)

	// THEN
	require.Len(t, rw.deadlines, 4)
	assert.True(t, rw.deadlines[1].IsZero())
	assert.True(t, rw.deadlines[2].Before(secondReadStartedAt))
	assert.True(t, rw.deadlines[3].IsZero())
}

func TestReadIdleAllowsApplicationPauseLongerThanIdleTimeout(t *testing.T) {
	t.Parallel()

	// GIVEN
	body := &bodyRecorder{Reader: strings.NewReader("ab")}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://heimdall.local/test", nil)
	req.Body = body
	rw := &readDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	idleTimeout := 20 * time.Millisecond
	var secondReadStartedAt time.Time
	handler := New(zerolog.Nop(), WithRequestBodyReadIdleTimeout(idleTimeout))(http.HandlerFunc(
		func(_ http.ResponseWriter, req *http.Request) {
			buffer := make([]byte, 1)
			_, firstErr := req.Body.Read(buffer)
			require.NoError(t, firstErr)

			time.Sleep(3 * idleTimeout)
			secondReadStartedAt = time.Now()
			_, secondErr := req.Body.Read(buffer)
			require.NoError(t, secondErr)
		},
	))

	// WHEN
	handler.ServeHTTP(rw, req)

	// THEN
	require.Len(t, rw.deadlines, 4)
	assert.True(t, rw.deadlines[1].IsZero())
	assert.WithinDuration(t, secondReadStartedAt.Add(idleTimeout), rw.deadlines[2], 10*time.Millisecond)
	assert.True(t, rw.deadlines[3].IsZero())
}

func TestRequestBodyReadIdleOverNetwork(t *testing.T) {
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
			server := httptest.NewServer(New(zerolog.Nop(), WithRequestBodyReadIdleTimeout(tc.timeout))(http.HandlerFunc(
				func(rw http.ResponseWriter, req *http.Request) {
					close(readStarted)

					body, err := io.ReadAll(req.Body)
					result <- struct {
						body string
						err  error
					}{body: string(body), err: err}
					rw.WriteHeader(http.StatusNoContent)
				},
			)))
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

func TestReadHardTimeoutOverNetwork(t *testing.T) {
	result, elapsed := readSlowBodyOverNetwork(
		t,
		180*time.Millisecond,
		120*time.Millisecond,
		0,
		"4",
		[]string{"1", "2", "3", "4"},
		70*time.Millisecond,
	)

	require.Error(t, result.err)
	assertTimeoutError(t, result.err)
	assert.Less(t, elapsed, 500*time.Millisecond)
}

func TestReadMinimumRateOverNetwork(t *testing.T) {
	result, elapsed := readSlowBodyOverNetwork(
		t,
		0,
		250*time.Millisecond,
		50,
		"6",
		[]string{"1", "2", "3", "4", "5", "6"},
		100*time.Millisecond,
	)

	require.Error(t, result.err)
	assertTimeoutError(t, result.err)
	assert.Less(t, elapsed, 700*time.Millisecond)
}

func TestReadMinimumRateAllowsSufficientProgressOverNetwork(t *testing.T) {
	result, elapsed := readSlowBodyOverNetwork(
		t,
		0,
		250*time.Millisecond,
		8,
		"4",
		[]string{"1", "2", "3", "4"},
		100*time.Millisecond,
	)

	require.NoError(t, result.err)
	assert.Equal(t, "1234", result.body)
	assert.GreaterOrEqual(t, elapsed, 300*time.Millisecond)
}

type bodyReadResult struct {
	body string
	err  error
}

func readSlowBodyOverNetwork(
	t *testing.T,
	readTimeout time.Duration,
	readIdleTimeout time.Duration,
	readMinRate int64,
	contentLength string,
	bodyParts []string,
	writeInterval time.Duration,
) (bodyReadResult, time.Duration) {
	t.Helper()

	result := make(chan bodyReadResult, 1)
	readStarted := make(chan struct{})
	server := httptest.NewUnstartedServer(New(
		zerolog.Nop(),
		WithRequestReadTimeout(readTimeout),
		WithRequestBodyReadIdleTimeout(readIdleTimeout),
		WithRequestBodyReadMinRate(readMinRate),
	)(http.HandlerFunc(
		func(rw http.ResponseWriter, req *http.Request) {
			close(readStarted)

			body, err := io.ReadAll(req.Body)
			result <- bodyReadResult{body: string(body), err: err}
			rw.WriteHeader(http.StatusNoContent)
		},
	)))
	server.Config.ReadTimeout = readTimeout
	server.Start()
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", serverURL.Host)
	require.NoError(t, err)
	defer conn.Close()

	_, err = io.WriteString(
		conn,
		"POST / HTTP/1.1\r\nHost: "+serverURL.Host+"\r\nContent-Length: "+contentLength+"\r\n\r\n",
	)
	require.NoError(t, err)

	select {
	case <-readStarted:
	case <-time.After(time.Second):
		require.FailNow(t, "request body read did not start")
	}

	startedAt := time.Now()
	go func() {
		for idx, data := range bodyParts {
			if idx > 0 {
				time.Sleep(writeInterval)
			}

			if _, err := io.WriteString(conn, data); err != nil {
				return
			}
		}
	}()

	select {
	case res := <-result:
		return res, time.Since(startedAt)
	case <-time.After(2 * time.Second):
		require.FailNow(t, "request body read did not complete")
	}

	return bodyReadResult{}, 0
}

func assertTimeoutError(t *testing.T, err error) {
	t.Helper()

	var netErr net.Error
	assert.True(t, errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout())
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}
