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

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type manager struct {
	mu sync.RWMutex

	logger      zerolog.Logger
	providers   map[string]types.Provider
	bindings    map[bindingKey]*binding
	started     bool
	watchCancel context.CancelFunc
}

func newManager(appCtx app.Context) (*manager, error) {
	cfg := appCtx.Config()
	if cfg == nil {
		return nil, errorchain.NewWithMessage(pipeline.ErrConfiguration,
			"application config is not initialized")
	}

	providers := make([]types.Provider, 0, len(cfg.SecretManagement))
	for provName, provCfg := range cfg.SecretManagement {
		provider, err := registry.Create(appCtx, provCfg.Type, provName, provCfg.Config)
		if err != nil {
			return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
				"failed creating secret source '%s' of type '%s'", provName, provCfg.Type).
				CausedBy(err)
		}

		providers = append(providers, provider)
	}

	return createManager(appCtx.Logger(), providers...), nil
}

func createManager(logger zerolog.Logger, providers ...types.Provider) *manager {
	mgr := &manager{
		logger:    logger,
		providers: make(map[string]types.Provider, len(providers)),
		bindings:  make(map[bindingKey]*binding),
	}

	for _, provider := range providers {
		mgr.providers[provider.Name()] = provider
	}

	return mgr
}

func (m *manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		return nil
	}

	watchCtx, cancel := context.WithCancel(context.Background())
	startedProviders := make([]types.Provider, 0, len(m.providers))

	for source, provider := range m.providers {
		err := provider.Start(watchCtx, func(evt types.ChangeEvent) { //nolint:contextcheck
			m.dispatchChange(source, evt)
		})
		ctxErr := ctx.Err()

		if err != nil || ctxErr != nil {
			cancel()

			for _, startedProvider := range startedProviders {
				_ = startedProvider.Stop(context.Background()) //nolint:contextcheck
			}

			return x.IfThenElse(err != nil, err, ctxErr)
		}

		startedProviders = append(startedProviders, provider)
	}

	m.watchCancel = cancel
	m.started = true

	return nil
}

func (m *manager) Stop(ctx context.Context) error {
	m.mu.Lock()

	cancel := m.watchCancel
	m.watchCancel = nil
	m.started = false

	bindings := make([]*binding, 0, len(m.bindings))
	for key, bdg := range m.bindings {
		bindings = append(bindings, bdg)
		delete(m.bindings, key)
	}

	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	stopErr := m.stopProviders(ctx)

	for _, bdg := range bindings {
		bdg.stop()
	}

	return stopErr
}

func (m *manager) ResolveSecret(ctx context.Context, source, ref string) (Secret, error) {
	provider, err := m.provider(source)
	if err != nil {
		return nil, err
	}

	return provider.ResolveSecret(ctx, ref)
}

func (m *manager) ResolveCredentials(ctx context.Context, source, ref string) (Credentials, error) {
	provider, err := m.provider(source)
	if err != nil {
		return nil, err
	}

	return provider.ResolveCredentials(ctx, ref)
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

	key := bindingKey{source: source, ref: ref}

	bdg := m.bindings[key]
	if bdg == nil {
		bdg = newBinding(source, ref, m.logger)
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

func (m *manager) stopProviders(ctx context.Context) error {
	var stopErr error
	for _, provider := range m.providers {
		if err := provider.Stop(ctx); err != nil && stopErr == nil {
			stopErr = err
		}
	}

	return stopErr
}

type bindingKey struct {
	source string
	ref    string
}

type binding struct {
	source string
	ref    string
	logger zerolog.Logger

	nextSubscriberID uint64
	mut              sync.RWMutex
	callbacks        map[uint64]func(context.Context) error
	events           chan struct{}
	done             chan struct{}
}

func newBinding(source, ref string, logger zerolog.Logger) *binding {
	bdg := &binding{
		source:    source,
		ref:       ref,
		logger:    logger,
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
				b.logger.Warn().
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
