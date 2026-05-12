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

package listener

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnWrite(t *testing.T) {
	tests := map[string]struct {
		setupConn func() *conn
		assert    func(t *testing.T, written int, err error, recorder *connRecorder)
	}{
		"writes without deadline reset": {
			setupConn: func() *conn {
				return &conn{Conn: &connRecorder{}}
			},
			assert: func(t *testing.T, written int, err error, recorder *connRecorder) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, 4, written)
				assert.Empty(t, recorder.writeDeadlines)
				assert.Equal(t, [][]byte{[]byte("test")}, recorder.writes)
			},
		},
		"resets write deadline before next write": {
			setupConn: func() *conn {
				c := &conn{Conn: &connRecorder{}}
				c.writeTimeout.Store(int64(5 * time.Second))
				c.resetDeadline.Store(true)
				c.bytesWritten.Store(1)

				return c
			},
			assert: func(t *testing.T, written int, err error, recorder *connRecorder) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, 4, written)
				require.Len(t, recorder.writeDeadlines, 1)
				assert.WithinDuration(t, time.Now().Add(5*time.Second), recorder.writeDeadlines[0], time.Second)
				assert.Equal(t, [][]byte{[]byte("test")}, recorder.writes)
			},
		},
		"returns deadline reset error": {
			setupConn: func() *conn {
				c := &conn{Conn: &connRecorder{setWriteDeadlineErr: assert.AnError}}
				c.writeTimeout.Store(int64(time.Second))
				c.resetDeadline.Store(true)
				c.bytesWritten.Store(1)

				return c
			},
			assert: func(t *testing.T, written int, err error, recorder *connRecorder) {
				t.Helper()

				require.ErrorContains(t, err, assert.AnError.Error())
				assert.Zero(t, written)
				assert.Empty(t, recorder.writes)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := tc.setupConn()
			recorder := c.Conn.(*connRecorder) //nolint:forcetypeassert

			written, err := c.Write([]byte("test"))

			tc.assert(t, written, err, recorder)
		})
	}
}

func TestConnSetDeadline(t *testing.T) {
	t.Run("disables reset for zero deadline", func(t *testing.T) {
		recorder := &connRecorder{}
		wrappedConn := &conn{Conn: recorder}
		wrappedConn.resetDeadline.Store(true)

		err := wrappedConn.SetDeadline(time.Time{})

		require.NoError(t, err)
		assert.False(t, wrappedConn.resetDeadline.Load())
		require.Len(t, recorder.deadlines, 1)
		assert.True(t, recorder.deadlines[0].IsZero())
	})

	t.Run("stores timeout for non zero deadline", func(t *testing.T) {
		recorder := &connRecorder{}
		wrappedConn := &conn{Conn: recorder}
		deadline := time.Now().Add(5 * time.Second)

		err := wrappedConn.SetDeadline(deadline)

		require.NoError(t, err)
		assert.InDelta(t, int64(5*time.Second), wrappedConn.writeTimeout.Load(), float64(time.Second))
		require.Len(t, recorder.deadlines, 1)
		assert.Equal(t, deadline, recorder.deadlines[0])
	})
}

func TestConnSetWriteDeadline(t *testing.T) {
	t.Run("disables reset for zero deadline", func(t *testing.T) {
		recorder := &connRecorder{}
		wrappedConn := &conn{Conn: recorder}
		wrappedConn.resetDeadline.Store(true)

		err := wrappedConn.SetWriteDeadline(time.Time{})

		require.NoError(t, err)
		assert.False(t, wrappedConn.resetDeadline.Load())
		require.Len(t, recorder.writeDeadlines, 1)
		assert.True(t, recorder.writeDeadlines[0].IsZero())
	})

	t.Run("stores timeout for non zero deadline", func(t *testing.T) {
		recorder := &connRecorder{}
		wrappedConn := &conn{Conn: recorder}
		deadline := time.Now().Add(5 * time.Second)

		err := wrappedConn.SetWriteDeadline(deadline)

		require.NoError(t, err)
		assert.InDelta(t, int64(5*time.Second), wrappedConn.writeTimeout.Load(), float64(time.Second))
		require.Len(t, recorder.writeDeadlines, 1)
		assert.Equal(t, deadline, recorder.writeDeadlines[0])
	})
}

func TestConnMonitorAndResetDeadlines(t *testing.T) {
	wrappedConn := &conn{}

	wrappedConn.MonitorAndResetDeadlines(true)
	assert.True(t, wrappedConn.resetDeadline.Load())

	wrappedConn.MonitorAndResetDeadlines(false)
	assert.False(t, wrappedConn.resetDeadline.Load())
}

type connRecorder struct {
	deadlines           []time.Time
	writeDeadlines      []time.Time
	writes              [][]byte
	setWriteDeadlineErr error
}

func (r *connRecorder) Read(_ []byte) (int, error)        { return 0, io.EOF }
func (r *connRecorder) Close() error                      { return nil }
func (r *connRecorder) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (r *connRecorder) RemoteAddr() net.Addr              { return &net.TCPAddr{} }
func (r *connRecorder) SetReadDeadline(_ time.Time) error { return nil }

func (r *connRecorder) Write(data []byte) (int, error) {
	r.writes = append(r.writes, append([]byte(nil), data...))

	return len(data), nil
}

func (r *connRecorder) SetDeadline(deadline time.Time) error {
	r.deadlines = append(r.deadlines, deadline)

	return nil
}

func (r *connRecorder) SetWriteDeadline(deadline time.Time) error {
	if r.setWriteDeadlineErr != nil {
		return r.setWriteDeadlineErr
	}

	r.writeDeadlines = append(r.writeDeadlines, deadline)

	return nil
}
