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
	"time"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	errTunnelRegistrySealed = errors.New("tunnel registry is sealed")
	errTunnelDrain          = errors.New("failed to drain tunnels")
)

const (
	tunnelCleanupTailFraction = 10
	maxTunnelCleanupTail      = 100 * time.Millisecond
)

type tunnelRegistry struct {
	mu      sync.Mutex
	entries map[*tunnelEndpoint]struct{}
	drained chan struct{}
	sealed  bool
}

func newTunnelRegistry() *tunnelRegistry {
	return &tunnelRegistry{
		entries: make(map[*tunnelEndpoint]struct{}),
		drained: make(chan struct{}),
	}
}

func (r *tunnelRegistry) track(
	conn io.ReadWriteCloser,
	teardownStrategy connectionTeardownStrategy,
) (*tunnelEndpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.sealed {
		return nil, errTunnelRegistrySealed
	}

	endpoint := &tunnelEndpoint{
		conn:             conn,
		teardownStrategy: teardownStrategy,
		registry:         r,
	}
	r.entries[endpoint] = struct{}{}

	return endpoint, nil
}

func (r *tunnelRegistry) sealAndWait(ctx context.Context) error {
	r.mu.Lock()
	r.sealLocked()
	drained := r.drained
	r.mu.Unlock()

	select {
	case <-drained:
		return nil
	default:
	}

	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		select {
		case <-drained:
			return nil
		default:
			return errorchain.New(errTunnelDrain).CausedBy(ctx.Err())
		}
	}
}

func (r *tunnelRegistry) shutdown(ctx context.Context) error {
	drainCtx, cancel := tunnelDrainContext(ctx)
	defer cancel()

	drainErr := r.sealAndWait(drainCtx)
	if drainErr == nil {
		return nil
	}

	shutdownErr := r.shutdownRemaining(ctx)
	if shutdownErr == nil {
		return drainErr
	}

	return errorchain.List(drainErr, shutdownErr)
}

func (r *tunnelRegistry) shutdownRemaining(ctx context.Context) error {
	r.mu.Lock()
	entries := make([]*tunnelEndpoint, 0, len(r.entries))
	for entry := range r.entries {
		entries = append(entries, entry)
	}
	r.mu.Unlock()

	teardownTunnelEndpoints(ctx, entries)

	errs := make([]error, 0, len(entries))
	for _, entry := range entries {
		if err := entry.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errorchain.List(errs...)
}

func teardownTunnelEndpoints(ctx context.Context, entries []*tunnelEndpoint) {
	var wg sync.WaitGroup
	for _, entry := range entries {
		wg.Go(func() {
			entry.teardown(ctx)
		})
	}

	wg.Wait()
}

func tunnelDrainContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		return context.WithCancel(ctx)
	}

	tail := min(remaining/tunnelCleanupTailFraction, maxTunnelCleanupTail)

	return context.WithDeadline(ctx, deadline.Add(-tail))
}

func (r *tunnelRegistry) sealLocked() {
	if r.sealed {
		return
	}

	r.sealed = true
	if len(r.entries) == 0 {
		close(r.drained)
	}
}

func (r *tunnelRegistry) remove(entry *tunnelEndpoint) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.entries, entry)
	if r.sealed && len(r.entries) == 0 {
		select {
		case <-r.drained:
		default:
			close(r.drained)
		}
	}
}

type tunnelEndpoint struct {
	conn             io.ReadWriteCloser
	teardownStrategy connectionTeardownStrategy

	registry *tunnelRegistry
	once     sync.Once
	closeErr error
}

func (e *tunnelEndpoint) Read(data []byte) (int, error) {
	return e.conn.Read(data)
}

func (e *tunnelEndpoint) Write(data []byte) (int, error) {
	return e.conn.Write(data)
}

func (e *tunnelEndpoint) Close() error {
	return e.close(e.conn.Close)
}

func (e *tunnelEndpoint) teardown(ctx context.Context) {
	e.teardownStrategy.apply(ctx, e.conn)
}

func (e *tunnelEndpoint) close(closeConnection func() error) error {
	e.once.Do(func() {
		e.closeErr = closeConnection()
		e.registry.remove(e)
	})

	return e.closeErr
}
