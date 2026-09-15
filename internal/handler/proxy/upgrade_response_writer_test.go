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
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type hijackResponseWriter struct {
	conn net.Conn
	err  error
}

func (*hijackResponseWriter) Header() http.Header            { return make(http.Header) }
func (*hijackResponseWriter) Write(data []byte) (int, error) { return len(data), nil }
func (*hijackResponseWriter) WriteHeader(int)                {}
func (w *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.err != nil {
		return nil, nil, w.err
	}

	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

type unwrapResponseWriter struct {
	http.ResponseWriter
}

func (w *unwrapResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestUpgradeResponseWriterHijack(t *testing.T) {
	t.Parallel()

	type testContext struct {
		responseWriter   http.ResponseWriter
		teardownStrategy connectionTeardownStrategy
		sourceConn       *capabilityTunnelConn
	}

	hijackErr := errors.New("hijack failed")
	closeErr := errors.New("close failed")

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, tracker *TunnelTrackerMock) testContext
		assert func(t *testing.T, ctx testContext, conn net.Conn, rw *bufio.ReadWriter, err error)
	}{
		"tracks successful hijack": {
			setup: func(t *testing.T, tracker *TunnelTrackerMock) testContext {
				t.Helper()

				conn := new(capabilityTunnelConn)
				strategy := noopConnectionTeardownStrategy{}
				endpoint := &tunnelEndpoint{conn: conn}
				tracker.EXPECT().track(conn, strategy).Return(endpoint, nil)

				return testContext{
					responseWriter:   &unwrapResponseWriter{ResponseWriter: &hijackResponseWriter{conn: conn}},
					teardownStrategy: strategy,
					sourceConn:       conn,
				}
			},
			assert: func(t *testing.T, ctx testContext, conn net.Conn, rw *bufio.ReadWriter, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, conn)
				require.NotNil(t, rw)
				closeWriter, ok := conn.(closeWriter)
				require.True(t, ok)
				require.NoError(t, closeWriter.CloseWrite())
				assert.Equal(t, int32(1), ctx.sourceConn.closeWriteCalls.Load())
			},
		},
		"does not track failed hijack": {
			setup: func(t *testing.T, _ *TunnelTrackerMock) testContext {
				t.Helper()

				return testContext{
					responseWriter:   &hijackResponseWriter{err: hijackErr},
					teardownStrategy: noopConnectionTeardownStrategy{},
				}
			},
			assert: func(t *testing.T, _ testContext, conn net.Conn, rw *bufio.ReadWriter, err error) {
				t.Helper()

				require.ErrorIs(t, err, hijackErr)
				assert.Nil(t, conn)
				assert.Nil(t, rw)
			},
		},
		"rejects hijack if tunnel cannot be tracked": {
			setup: func(t *testing.T, tracker *TunnelTrackerMock) testContext {
				t.Helper()

				conn := new(capabilityTunnelConn)
				strategy := noopConnectionTeardownStrategy{}
				tracker.EXPECT().track(conn, strategy).Return(nil, errTunnelRegistrySealed)

				return testContext{
					responseWriter:   &hijackResponseWriter{conn: conn},
					teardownStrategy: strategy,
					sourceConn:       conn,
				}
			},
			assert: func(t *testing.T, ctx testContext, conn net.Conn, rw *bufio.ReadWriter, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTunnelRegistrySealed)
				assert.Nil(t, conn)
				assert.Nil(t, rw)
				assert.Equal(t, int32(1), ctx.sourceConn.closeCalls.Load())
			},
		},
		"ignores close failure after rejected hijack": {
			setup: func(t *testing.T, tracker *TunnelTrackerMock) testContext {
				t.Helper()

				conn := &capabilityTunnelConn{
					closeErr: closeErr,
				}
				strategy := noopConnectionTeardownStrategy{}
				tracker.EXPECT().track(conn, strategy).Return(nil, errTunnelRegistrySealed)

				return testContext{
					responseWriter:   &hijackResponseWriter{conn: conn},
					teardownStrategy: strategy,
					sourceConn:       conn,
				}
			},
			assert: func(t *testing.T, ctx testContext, conn net.Conn, rw *bufio.ReadWriter, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTunnelRegistrySealed)
				require.NotErrorIs(t, err, closeErr)
				assert.Nil(t, conn)
				assert.Nil(t, rw)
				assert.Equal(t, int32(1), ctx.sourceConn.closeCalls.Load())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			tracker := NewTunnelTrackerMock(t)
			ctx := tc.setup(t, tracker)
			writer := &upgradeResponseWriter{
				ResponseWriter:   ctx.responseWriter,
				tunnels:          tracker,
				teardownStrategy: ctx.teardownStrategy,
			}

			// WHEN
			conn, rw, err := writer.Hijack()

			// THEN
			tc.assert(t, ctx, conn, rw, err)
		})
	}
}

func TestHijackedConnCloseUnregistersTunnel(t *testing.T) {
	t.Parallel()

	// GIVEN
	registry := newTunnelRegistry()
	conn, peer := net.Pipe()
	defer peer.Close()
	endpoint, err := registry.track(conn, noopConnectionTeardownStrategy{})
	require.NoError(t, err)
	wrapped := newHijackedConn(conn, endpoint)

	// WHEN
	require.NoError(t, wrapped.Close())
	require.NoError(t, wrapped.Close())

	// THEN
	assert.Equal(t, 0, tunnelRegistrySize(registry))
}

func TestHijackedConnPreservesReverseProxyCopyCapabilities(t *testing.T) {
	t.Parallel()

	// GIVEN
	registry := newTunnelRegistry()
	conn := new(capabilityTunnelConn)
	endpoint, err := registry.track(conn, noopConnectionTeardownStrategy{})
	require.NoError(t, err)
	wrapped := newHijackedConn(conn, endpoint)

	// WHEN
	closeWriter, ok := wrapped.(closeWriter)
	require.True(t, ok)
	require.NoError(t, closeWriter.CloseWrite())

	readerFrom, ok := wrapped.(io.ReaderFrom)
	require.True(t, ok)
	read, err := readerFrom.ReadFrom(strings.NewReader("payload"))

	// THEN
	require.NoError(t, err)
	assert.Equal(t, int64(len("payload")), read)
	assert.Equal(t, int32(1), conn.closeWriteCalls.Load())
	assert.Equal(t, int32(1), conn.readFromCalls.Load())
	require.NoError(t, wrapped.Close())
}

func TestHijackedConnDoesNotInventCloseWriteCapability(t *testing.T) {
	t.Parallel()

	// GIVEN
	registry := newTunnelRegistry()
	conn, peer := net.Pipe()
	defer peer.Close()
	endpoint, err := registry.track(conn, noopConnectionTeardownStrategy{})
	require.NoError(t, err)
	wrapped := newHijackedConn(conn, endpoint)

	// THEN
	_, ok := wrapped.(closeWriter)
	assert.False(t, ok)
	require.NoError(t, wrapped.Close())
}
