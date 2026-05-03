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
	"sync/atomic"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type managedProvider struct {
	provider               types.Provider
	accessFromRulesAllowed bool
}

type manager struct {
	mu sync.RWMutex

	logger      zerolog.Logger
	providers   map[string]managedProvider
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

	providers := make([]managedProvider, 0, len(cfg.SecretManagement))
	for provName, provCfg := range cfg.SecretManagement {
		provider, err := registry.Create(appCtx, provCfg.Type, provName, provCfg.Config)
		if err != nil {
			return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
				"failed creating secret source '%s' of type '%s'", provName, provCfg.Type).
				CausedBy(err)
		}

		providers = append(providers, managedProvider{
			provider:               provider,
			accessFromRulesAllowed: provCfg.AllowInRules,
		})
	}

	return createManager(appCtx.Logger(), providers...), nil
}

func createManager(logger zerolog.Logger, providers ...managedProvider) *manager {
	mgr := &manager{
		logger:    logger,
		providers: make(map[string]managedProvider, len(providers)),
		bindings:  make(map[bindingKey]*binding, 10),
	}

	for _, mp := range providers {
		mgr.providers[mp.provider.Name()] = mp
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

	for _, mp := range m.providers {
		err := mp.provider.Start(watchCtx, func(evt types.ChangeEvent) { //nolint:contextcheck
			m.dispatchChange(evt)
		})
		ctxErr := ctx.Err()

		if err != nil || ctxErr != nil {
			cancel()

			for _, startedProvider := range startedProviders {
				_ = startedProvider.Stop(context.Background()) //nolint:contextcheck
			}

			return x.IfThenElse(err != nil, err, ctxErr)
		}

		startedProviders = append(startedProviders, mp.provider)
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

func (m *manager) ResolveSecret(ctx context.Context, ref Reference) (Secret, error) {
	provider, err := m.provider(ref)
	if err != nil {
		return nil, err
	}

	return provider.ResolveSecret(ctx, types.Selector{Value: ref.Selector, Namespace: ref.Namespace})
}

func (m *manager) ResolveSecretSet(ctx context.Context, ref Reference) ([]Secret, error) {
	provider, err := m.provider(ref)
	if err != nil {
		return nil, err
	}

	return provider.ResolveSecretSet(ctx, types.Selector{Value: ref.Selector, Namespace: ref.Namespace})
}

func (m *manager) ResolveCredentials(ctx context.Context, ref Reference) (Credentials, error) {
	provider, err := m.provider(ref)
	if err != nil {
		return nil, err
	}

	return provider.ResolveCredentials(ctx, types.Selector{Value: ref.Selector, Namespace: ref.Namespace})
}

func (m *manager) Subscribe(ref Reference, cb func(context.Context) error) (func(), error) {
	if cb == nil {
		return nil, fmt.Errorf("%w: callback must not be nil", ErrSubscribeFailed)
	}

	if _, err := m.provider(ref); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := bindingKey{source: ref.Source, selector: ref.Selector, namespace: ref.Namespace}

	bdg := m.bindings[key]
	if bdg == nil {
		bdg = newBinding(key, m.logger)
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

func (m *manager) provider(ref Reference) (types.Provider, error) {
	m.mu.RLock()
	mp, ok := m.providers[ref.Source]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: '%s'", ErrProviderNotFound, ref.Source)
	}

	if ref.RuleContext && !mp.accessFromRulesAllowed {
		return nil, ErrSecretSourceForbidden
	}

	return mp.provider, nil
}

func (m *manager) dispatchChange(evt types.ChangeEvent) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(evt.Selectors) == 0 {
		for key, bdg := range m.bindings {
			if key.source != evt.Source {
				continue
			}

			if evt.Namespace != "" && key.namespace != evt.Namespace {
				continue
			}

			bdg.enqueue()
		}

		return
	}

	for _, selector := range evt.Selectors {
		bdg := m.bindings[bindingKey{
			source:    evt.Source,
			selector:  selector,
			namespace: evt.Namespace,
		}]
		if bdg != nil {
			bdg.enqueue()
		}
	}
}

func (m *manager) stopProviders(ctx context.Context) error {
	var stopErr error
	for _, mp := range m.providers {
		if err := mp.provider.Stop(ctx); err != nil && stopErr == nil {
			stopErr = err
		}
	}

	return stopErr
}

type bindingKey struct {
	source    string
	selector  string
	namespace string
}

type binding struct {
	bindingKey

	logger           zerolog.Logger
	nextSubscriberID uint64
	mut              sync.RWMutex
	callbacks        map[uint64]func(context.Context) error

	events chan struct{}
	done   chan struct{}

	pending atomic.Bool
}

func newBinding(bk bindingKey, logger zerolog.Logger) *binding {
	bdg := &binding{
		bindingKey: bk,
		logger:     logger,
		callbacks:  make(map[uint64]func(context.Context) error),
		events:     make(chan struct{}, 1),
		done:       make(chan struct{}),
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
	if b.pending.CompareAndSwap(false, true) {
		b.events <- struct{}{}
	}
}

func (b *binding) run() {
	defer close(b.done)

	for range b.events {
		for {
			b.pending.Store(false)
			b.runCallbacks()

			if !b.pending.Load() {
				break
			}

			// Drain the signal enqueued while callbacks were running.
			select {
			case <-b.events:
			default:
			}
		}
	}
}

func (b *binding) runCallbacks() {
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
				Str("_namespace", b.namespace).
				Str("_ref", b.selector).
				Msg("Secret update callback failed")
		}
	}
}

func (b *binding) stop() {
	close(b.events)
	<-b.done
}
