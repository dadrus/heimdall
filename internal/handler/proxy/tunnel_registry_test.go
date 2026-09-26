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
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type orderedTunnelConnection struct {
	events *[]string
}

func (*orderedTunnelConnection) Read([]byte) (int, error)       { return 0, io.EOF }
func (*orderedTunnelConnection) Write(data []byte) (int, error) { return len(data), nil }
func (c *orderedTunnelConnection) Close() error {
	*c.events = append(*c.events, "close")

	return nil
}

type orderedConnectionTeardownStrategy struct {
	events *[]string
}

func (s orderedConnectionTeardownStrategy) apply(context.Context, io.ReadWriteCloser) {
	*s.events = append(*s.events, "teardown")
}

type teardownOrderState struct {
	teardowns        atomic.Int32
	closedTooEarly   atomic.Bool
	expectedTeardown int32
}

type teardownOrderStrategy struct {
	state *teardownOrderState
}

func (s teardownOrderStrategy) apply(context.Context, io.ReadWriteCloser) {
	s.state.teardowns.Add(1)
}

type teardownOrderConnection struct {
	testTunnelConnection

	state *teardownOrderState
}

func (c *teardownOrderConnection) Close() error {
	if c.state.teardowns.Load() != c.state.expectedTeardown {
		c.state.closedTooEarly.Store(true)
	}

	return c.testTunnelConnection.Close()
}

func tunnelRegistrySize(r *tunnelRegistry) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.entries)
}

func TestTunnelEndpointCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	// GIVEN
	registry := newTunnelRegistry()
	conn := new(testTunnelConnection)

	endpoint, err := registry.track(conn, noopConnectionTeardownStrategy{})
	require.NoError(t, err)
	require.Equal(t, 1, tunnelRegistrySize(registry))

	// WHEN
	require.NoError(t, endpoint.Close())
	require.NoError(t, endpoint.Close())

	// THEN
	assert.Equal(t, int32(1), conn.closeCalls.Load())
	assert.Equal(t, 0, tunnelRegistrySize(registry))
}

func TestTunnelEndpointCloseAndTeardown(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		teardown       bool
		expectedEvents []string
		expectedSize   int
	}{
		"natural close delegates close": {
			expectedEvents: []string{"close"},
		},
		"teardown delegates strategy without closing": {
			teardown:       true,
			expectedEvents: []string{"teardown"},
			expectedSize:   1,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			registry := newTunnelRegistry()
			events := make([]string, 0, 2)
			conn := &orderedTunnelConnection{events: &events}
			endpoint, err := registry.track(conn, orderedConnectionTeardownStrategy{events: &events})
			require.NoError(t, err)

			// WHEN
			if tc.teardown {
				endpoint.teardown(t.Context())
			} else {
				err = endpoint.Close()
				require.NoError(t, err)
			}

			// THEN
			assert.Equal(t, tc.expectedEvents, events)
			assert.Equal(t, tc.expectedSize, tunnelRegistrySize(registry))

			if tc.teardown {
				require.NoError(t, endpoint.Close())
			}
		})
	}
}

func TestTunnelEndpointTeardownPrecedesClose(t *testing.T) {
	t.Parallel()

	// GIVEN
	registry := newTunnelRegistry()
	events := make([]string, 0, 2)
	conn := &orderedTunnelConnection{events: &events}
	endpoint, err := registry.track(conn, orderedConnectionTeardownStrategy{events: &events})
	require.NoError(t, err)

	// WHEN
	endpoint.teardown(t.Context())
	require.NoError(t, endpoint.Close())

	// THEN
	assert.Equal(t, []string{"teardown", "close"}, events)
	assert.Equal(t, 0, tunnelRegistrySize(registry))
}

func TestTunnelRegistryShutdownTearsDownAllEndpointsBeforeClosing(t *testing.T) {
	t.Parallel()

	// GIVEN
	const endpointCount = 2
	state := &teardownOrderState{expectedTeardown: endpointCount}
	registry := newTunnelRegistry()
	connections := make([]*teardownOrderConnection, endpointCount)
	for idx := range connections {
		connections[idx] = &teardownOrderConnection{state: state}
		_, err := registry.track(connections[idx], teardownOrderStrategy{state: state})
		require.NoError(t, err)
	}

	// WHEN
	err := registry.shutdownRemaining(t.Context())

	// THEN
	require.NoError(t, err)
	assert.Equal(t, int32(endpointCount), state.teardowns.Load())
	assert.False(t, state.closedTooEarly.Load())
	for idx := range connections {
		assert.Equal(t, int32(1), connections[idx].closeCalls.Load())
	}
}

func TestTunnelRegistryShutdownWaitsForDrain(t *testing.T) {
	t.Parallel()

	// GIVEN
	registry := newTunnelRegistry()
	first, err := registry.track(new(testTunnelConnection), noopConnectionTeardownStrategy{})
	require.NoError(t, err)
	second, err := registry.track(new(testTunnelConnection), noopConnectionTeardownStrategy{})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- registry.shutdown(ctx)
	}()

	require.Eventually(t, func() bool {
		registry.mu.Lock()
		defer registry.mu.Unlock()

		return registry.sealed
	}, time.Second, 10*time.Millisecond)

	select {
	case err := <-shutdownDone:
		require.Failf(t, "shutdown returned early", "error: %v", err)
	default:
	}

	// WHEN
	require.NoError(t, first.Close())

	// THEN
	select {
	case err := <-shutdownDone:
		require.Failf(t, "shutdown returned with one tunnel still tracked", "error: %v", err)
	default:
	}

	// WHEN
	require.NoError(t, second.Close())

	// THEN
	select {
	case err := <-shutdownDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		require.Fail(t, "shutdown did not finish after the registry drained")
	}
}

func TestTunnelRegistryShutdownRejectsNewEntries(t *testing.T) {
	t.Parallel()

	// GIVEN
	registry := newTunnelRegistry()
	require.NoError(t, registry.shutdown(t.Context()))
	conn := new(testTunnelConnection)

	// WHEN
	tracked, err := registry.track(conn, noopConnectionTeardownStrategy{})

	// THEN
	require.ErrorIs(t, err, errTunnelRegistrySealed)
	assert.Nil(t, tracked)
	assert.Equal(t, int32(0), conn.closeCalls.Load())
	assert.Equal(t, 0, tunnelRegistrySize(registry))
}

func TestTunnelRegistryShutdownClosesRemainingEndpoints(t *testing.T) {
	t.Parallel()

	// GIVEN
	firstCloseErr := errors.New("could not close first tunnel")
	secondCloseErr := errors.New("could not close second tunnel")
	registry := newTunnelRegistry()
	firstConn := &testTunnelConnection{closeErr: firstCloseErr}
	secondConn := &testTunnelConnection{closeErr: secondCloseErr}

	_, err := registry.track(firstConn, noopConnectionTeardownStrategy{})
	require.NoError(t, err)
	_, err = registry.track(secondConn, noopConnectionTeardownStrategy{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	shutdownDone := make(chan error, 1)

	// WHEN
	go func() {
		shutdownDone <- registry.shutdown(ctx)
	}()

	// THEN
	select {
	case err := <-shutdownDone:
		require.ErrorIs(t, err, errTunnelDrain)
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, firstCloseErr)
		require.ErrorIs(t, err, secondCloseErr)
	case <-time.After(time.Second):
		require.Fail(t, "shutdown deadlocked while endpoints unregistered themselves")
	}

	assert.Equal(t, int32(1), firstConn.closeCalls.Load())
	assert.Equal(t, int32(1), secondConn.closeCalls.Load())
	assert.Equal(t, 0, tunnelRegistrySize(registry))

	lateConn := new(testTunnelConnection)
	tracked, err := registry.track(lateConn, noopConnectionTeardownStrategy{})
	require.ErrorIs(t, err, errTunnelRegistrySealed)
	assert.Nil(t, tracked)
	assert.Equal(t, int32(0), lateConn.closeCalls.Load())
}

func TestTunnelRegistryShutdownHonorsContext(t *testing.T) {
	t.Parallel()

	// GIVEN
	registry := newTunnelRegistry()
	conn := new(testTunnelConnection)
	_, err := registry.track(conn, noopConnectionTeardownStrategy{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// WHEN
	err = registry.shutdown(ctx)

	// THEN
	require.ErrorIs(t, err, errTunnelDrain)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int32(1), conn.closeCalls.Load())
	assert.Equal(t, 0, tunnelRegistrySize(registry))
}

func TestTunnelDrainContext(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	parentDeadline, ok := parent.Deadline()
	require.True(t, ok)

	drainCtx, drainCancel := tunnelDrainContext(parent)
	defer drainCancel()

	drainDeadline, ok := drainCtx.Deadline()
	require.True(t, ok)
	assert.Equal(t, maxTunnelCleanupTail, parentDeadline.Sub(drainDeadline))
}

func TestTunnelRegistryConcurrentNaturalCloseAndShutdown(t *testing.T) {
	t.Parallel()

	// GIVEN
	registry := newTunnelRegistry()
	connections := make([]*testTunnelConnection, 64)
	endpoints := make([]*tunnelEndpoint, len(connections))
	for idx := range connections {
		connections[idx] = new(testTunnelConnection)
		entry, err := registry.track(connections[idx], noopConnectionTeardownStrategy{})
		require.NoError(t, err)
		endpoints[idx] = entry
	}

	var wg sync.WaitGroup
	for idx := 0; idx < len(endpoints); idx += 2 {
		entry := endpoints[idx]
		wg.Go(func() {
			assert.NoError(t, entry.Close())
		})
	}

	shutdownCtx, cancel := context.WithCancel(t.Context())
	cancel()

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- registry.shutdown(shutdownCtx)
	}()

	naturalDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(naturalDone)
	}()

	// THEN
	select {
	case <-naturalDone:
	case <-time.After(time.Second):
		require.Fail(t, "concurrent natural closes did not finish")
	}

	select {
	case err := <-shutdownDone:
		require.ErrorIs(t, err, errTunnelDrain)
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		require.Fail(t, "concurrent registry shutdown did not finish")
	}

	assert.Equal(t, 0, tunnelRegistrySize(registry))
	for _, conn := range connections {
		assert.Equal(t, int32(1), conn.closeCalls.Load())
	}
}
