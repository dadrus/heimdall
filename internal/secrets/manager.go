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

package secrets

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/dadrus/heimdall/internal/secrets/types"
)

type manager struct {
	mu sync.RWMutex

	providers       map[string]types.Provider
	watchersStarted map[string]bool
	bindings        map[bindingKey]*binding
}

func NewManager(providers ...types.Provider) Manager {
	mgr := &manager{
		providers:       make(map[string]types.Provider, len(providers)),
		watchersStarted: make(map[string]bool, len(providers)),
		bindings:        make(map[bindingKey]*binding),
	}

	for _, provider := range providers {
		if provider == nil {
			continue
		}

		mgr.providers[provider.Name()] = provider
	}

	return mgr
}

func (m *manager) ResolveSecret(ctx context.Context, source, ref string) (types.Secret, error) {
	provider, err := m.provider(source)
	if err != nil {
		return types.Secret{}, err
	}

	return provider.ResolveSecret(ctx, ref)
}

func (m *manager) ResolveSecrets(
	ctx context.Context,
	source, ref string,
	keys ...string,
) (map[string]types.Secret, error) {
	provider, err := m.provider(source)
	if err != nil {
		return nil, err
	}

	return provider.ResolveSecrets(ctx, ref, keys...)
}

func (m *manager) Subscribe(source, ref string, cb func(context.Context) error) (func(), error) {
	if cb == nil {
		return nil, fmt.Errorf("%w: callback must not be nil", ErrSubscribeFailed)
	}

	if _, err := m.provider(source); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.startWatcherLocked(source); err != nil {
		return nil, err
	}

	key := bindingKey{source: source, ref: ref}

	bdg := m.bindings[key]
	if bdg == nil {
		bdg = newBinding(source, ref)
		m.bindings[key] = bdg
	}

	subscriberID := bdg.addSubscriber(cb)

	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		bdg := m.bindings[key]
		if bdg == nil {
			return
		}

		if bdg.removeSubscriber(subscriberID) {
			return
		}

		bdg.stop()
		delete(m.bindings, key)
	}, nil
}

func (m *manager) provider(source string) (types.Provider, error) {
	m.mu.RLock()
	provider := m.providers[source]
	m.mu.RUnlock()

	if provider != nil {
		return provider, nil
	}

	return nil, fmt.Errorf("%w: '%s'", ErrProviderNotFound, source)
}

func (m *manager) startWatcherLocked(source string) error {
	if m.watchersStarted[source] {
		return nil
	}

	provider := m.providers[source]

	watchable, ok := provider.(types.Watchable)
	if !ok {
		m.watchersStarted[source] = true

		return nil
	}

	if err := watchable.Watch(context.Background(), func(evt types.ChangeEvent) {
		m.dispatchChange(source, evt)
	}); err != nil {
		return err
	}

	m.watchersStarted[source] = true

	return nil
}

func (m *manager) dispatchChange(source string, evt types.ChangeEvent) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(evt.Refs) == 0 {
		for key, b := range m.bindings {
			if key.source == source {
				b.enqueue()
			}
		}

		return
	}

	for _, ref := range evt.Refs {
		b := m.bindings[bindingKey{source: source, ref: ref}]
		if b != nil {
			b.enqueue()
		}
	}
}

type bindingKey struct {
	source string
	ref    string
}

type binding struct {
	source string
	ref    string

	nextSubscriberID uint64
	mut              sync.RWMutex
	callbacks        map[uint64]func(context.Context) error
	events           chan struct{}
	done             chan struct{}
}

func newBinding(source, ref string) *binding {
	bdg := &binding{
		source:    source,
		ref:       ref,
		callbacks: make(map[uint64]func(context.Context) error),
		events:    make(chan struct{}, 1),
		done:      make(chan struct{}),
	}

	go bdg.run()

	return bdg
}

func (b *binding) addSubscriber(cb func(context.Context) error) uint64 {
	b.mut.Lock()
	defer b.mut.Unlock()

	b.nextSubscriberID++
	id := b.nextSubscriberID
	b.callbacks[id] = cb

	return id
}

// removeSubscriber removes a callback and reports whether the binding still has callbacks.
func (b *binding) removeSubscriber(id uint64) bool {
	b.mut.Lock()
	defer b.mut.Unlock()

	delete(b.callbacks, id)

	return len(b.callbacks) > 0
}

func (b *binding) enqueue() {
	select {
	case b.events <- struct{}{}:
	default:
	}
}

func (b *binding) run() {
	defer close(b.done)

	for range b.events {
		b.mut.RLock()

		callbacks := make([]func(context.Context) error, 0, len(b.callbacks))
		for _, cb := range b.callbacks {
			callbacks = append(callbacks, cb)
		}

		b.mut.RUnlock()

		for _, cb := range callbacks {
			if err := cb(context.Background()); err != nil {
				log.Warn().
					Err(err).
					Str("_source", b.source).
					Str("_ref", b.ref).
					Msg("Secret update callback failed")
			}
		}
	}
}

func (b *binding) stop() {
	close(b.events)
	<-b.done
}
