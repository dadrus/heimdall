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
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingTunnelConnection struct {
	mu         sync.Mutex
	written    bytes.Buffer
	writeErr   error
	closeErr   error
	writeCalls atomic.Int32
	closeCalls atomic.Int32
}

func (*recordingTunnelConnection) Read([]byte) (int, error) { return 0, io.EOF }

func (c *recordingTunnelConnection) Write(data []byte) (int, error) {
	c.writeCalls.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.writeErr != nil {
		return 0, c.writeErr
	}

	return c.written.Write(data)
}

func (c *recordingTunnelConnection) Close() error {
	c.closeCalls.Add(1)

	return c.closeErr
}

func (c *recordingTunnelConnection) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	return bytes.Clone(c.written.Bytes())
}

func TestWebSocketGoingAwayTeardownStrategies(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		strategy connectionTeardownStrategy
		masked   bool
	}{
		"server strategy is unmasked": {
			strategy: webSocketServerGoingAwayTeardownStrategy,
		},
		"client strategy is masked": {
			strategy: webSocketClientGoingAwayTeardownStrategy,
			masked:   true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			conn := new(recordingTunnelConnection)

			// WHEN
			tc.strategy.apply(t.Context(), conn)

			// THEN
			assert.Equal(t, int32(0), conn.closeCalls.Load())
			assertWebSocketGoingAwayFrame(t, conn.bytes(), tc.masked)
		})
	}
}

func TestWebSocketGoingAwayTeardownStrategyIgnoresWriteFailures(t *testing.T) {
	t.Parallel()

	// GIVEN
	conn := &recordingTunnelConnection{writeErr: assert.AnError}

	// WHEN
	webSocketServerGoingAwayTeardownStrategy.apply(t.Context(), conn)

	// THEN
	assert.Equal(t, int32(1), conn.writeCalls.Load())
	assert.Equal(t, int32(0), conn.closeCalls.Load())
}

type blockingWebSocketConnection struct {
	writeStarted chan struct{}
	closed       chan struct{}
	closeOnce    sync.Once
	closeCalls   atomic.Int32
}

func (c *blockingWebSocketConnection) Read([]byte) (int, error) { return 0, io.EOF }

func (c *blockingWebSocketConnection) Write([]byte) (int, error) {
	close(c.writeStarted)
	<-c.closed

	return 0, net.ErrClosed
}

func (c *blockingWebSocketConnection) Close() error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() {
		close(c.closed)
	})

	return nil
}

func TestWebSocketGoingAwayTeardownStrategyDoesNotOutliveContext(t *testing.T) {
	t.Parallel()

	// GIVEN
	conn := &blockingWebSocketConnection{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(t.Context())
	teardownDone := make(chan struct{})
	go func() {
		webSocketServerGoingAwayTeardownStrategy.apply(ctx, conn)
		close(teardownDone)
	}()

	select {
	case <-conn.writeStarted:
	case <-time.After(time.Second):
		require.Fail(t, "websocket close frame write did not start")
	}

	// WHEN
	cancel()

	// THEN
	select {
	case <-teardownDone:
	case <-time.After(time.Second):
		require.Fail(t, "websocket teardown did not stop after context cancellation")
	}
	assert.Equal(t, int32(0), conn.closeCalls.Load())
	require.NoError(t, conn.Close())
}

func TestIsWebSocketUpgrade(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		headers  http.Header
		expected bool
	}{
		"websocket upgrade": {
			headers: http.Header{
				"Connection": []string{"keep-alive, Upgrade"},
				"Upgrade":    []string{"websocket"},
			},
			expected: true,
		},
		"websocket token is case insensitive": {
			headers: http.Header{
				"Connection": []string{"Upgrade"},
				"Upgrade":    []string{"WebSocket"},
			},
			expected: true,
		},
		"different upgrade protocol": {
			headers: http.Header{
				"Connection": []string{"Upgrade"},
				"Upgrade":    []string{"example"},
			},
		},
		"missing connection upgrade option": {
			headers: http.Header{
				"Upgrade": []string{"websocket"},
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
			req.Header = tc.headers

			// WHEN
			actual := isWebSocketUpgrade(req)

			// THEN
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestIsWebSocketUpgradeResponse(t *testing.T) {
	t.Parallel()

	webSocketRequest := func(t *testing.T) *http.Request {
		t.Helper()

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")

		return req
	}

	for uc, tc := range map[string]struct {
		statusCode int
		request    func(*testing.T) *http.Request
		headers    http.Header
		expected   bool
	}{
		"matching websocket upgrade response": {
			statusCode: http.StatusSwitchingProtocols,
			request:    webSocketRequest,
			headers: http.Header{
				"Connection": []string{"Upgrade"},
				"Upgrade":    []string{"websocket"},
			},
			expected: true,
		},
		"non switching response": {
			statusCode: http.StatusOK,
			request:    webSocketRequest,
			headers: http.Header{
				"Connection": []string{"Upgrade"},
				"Upgrade":    []string{"websocket"},
			},
		},
		"different response protocol": {
			statusCode: http.StatusSwitchingProtocols,
			request:    webSocketRequest,
			headers: http.Header{
				"Connection": []string{"Upgrade"},
				"Upgrade":    []string{"example"},
			},
		},
		"request is not websocket": {
			statusCode: http.StatusSwitchingProtocols,
			request: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "example")

				return req
			},
			headers: http.Header{
				"Connection": []string{"Upgrade"},
				"Upgrade":    []string{"websocket"},
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			res := &http.Response{
				StatusCode: tc.statusCode,
				Request:    tc.request(t),
				Header:     tc.headers,
			}

			// WHEN
			actual := isWebSocketUpgradeResponse(res)

			// THEN
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func assertWebSocketGoingAwayFrame(t *testing.T, frame []byte, masked bool) {
	t.Helper()

	if !masked {
		require.Len(t, frame, 4)
		assert.Equal(t, byte(0x88), frame[0])
		assert.Equal(t, byte(0x02), frame[1])
		assert.Equal(t, byte(webSocketCloseGoingAway>>8), frame[2])
		assert.Equal(t, byte(webSocketCloseGoingAway&0xff), frame[3])

		return
	}

	require.Len(t, frame, 8)
	assert.Equal(t, byte(0x88), frame[0])
	assert.Equal(t, byte(0x82), frame[1])

	maskKey := frame[2:6]
	assert.Equal(t, byte(webSocketCloseGoingAway>>8), frame[6]^maskKey[0])
	assert.Equal(t, byte(webSocketCloseGoingAway&0xff), frame[7]^maskKey[1])
}
