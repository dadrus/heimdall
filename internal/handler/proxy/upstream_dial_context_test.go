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
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
)

type writeDeadlineTrackingConn struct {
	net.Conn
	deadlines   []time.Time
	written     []byte
	writeErr    error
	deadlineErr error
}

func (c *writeDeadlineTrackingConn) Write(data []byte) (int, error) {
	c.written = append(c.written, data...)
	if c.writeErr != nil {
		return 0, c.writeErr
	}

	return len(data), nil
}

func (c *writeDeadlineTrackingConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)

	return c.deadlineErr
}

func TestIdleConnectionWriterWrite(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		writeErr    error
		deadlineErr error
	}{
		"successful write": {},
		"write error is preserved": {
			writeErr: errors.New("write failed"),
		},
		"deadline error is ignored": {
			deadlineErr: errors.New("deadline failed"),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			underlying := &writeDeadlineTrackingConn{
				writeErr:    tc.writeErr,
				deadlineErr: tc.deadlineErr,
			}
			idleTimeout := 5 * time.Second
			conn := &idleConnectionWriter{
				Conn:    underlying,
				timeout: idleTimeout,
			}
			startedAt := time.Now()

			// WHEN
			written, err := conn.Write([]byte("test"))

			// THEN
			if tc.writeErr != nil {
				require.ErrorIs(t, err, tc.writeErr)
				assert.Zero(t, written)
			} else {
				require.NoError(t, err)
				assert.Equal(t, 4, written)
			}

			assert.Equal(t, []byte("test"), underlying.written)
			require.Len(t, underlying.deadlines, 2)
			assert.WithinDuration(t, startedAt.Add(idleTimeout), underlying.deadlines[0], time.Second)
			assert.True(t, underlying.deadlines[1].IsZero())
		})
	}
}

func TestIdleConnectionWriterTerminatesBlockedWrite(t *testing.T) {
	t.Parallel()

	// GIVEN
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	conn := &idleConnectionWriter{
		Conn:    client,
		timeout: 100 * time.Millisecond,
	}

	// WHEN
	written, err := conn.Write([]byte("blocked"))

	// THEN
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout())
	assert.Zero(t, written)

	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, len("recovered"))
		_, err := io.ReadFull(peer, buffer)
		readDone <- err
	}()

	written, err = conn.Write([]byte("recovered"))
	require.NoError(t, err)
	assert.Equal(t, len("recovered"), written)
	require.NoError(t, <-readDone)
}

func TestNewUpstreamDialContext(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		writeIdleTimeout time.Duration
		expectWrapped    bool
	}{
		"write idle timeout disabled": {},
		"write idle timeout enabled": {
			writeIdleTimeout: 5 * time.Second,
			expectWrapped:    true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })

			cfg := config.UpstreamConnections{
				WriteIdleTimeout: tc.writeIdleTimeout,
			}
			dial := newUpstreamDialContext(cfg)

			// WHEN
			conn, err := dial(t.Context(), "tcp", listener.Addr().String())

			// THEN
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })

			peer, err := listener.Accept()
			require.NoError(t, err)
			t.Cleanup(func() { _ = peer.Close() })

			wrapped, ok := conn.(*idleConnectionWriter)
			if !tc.expectWrapped {
				assert.False(t, ok)

				return
			}

			require.True(t, ok)
			assert.Equal(t, tc.writeIdleTimeout, wrapped.timeout)
		})
	}
}
