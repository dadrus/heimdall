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
	"errors"
	"fmt"
	"maps"
	"sync"

	"github.com/dominikbraun/graph"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets/source"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type dependencyResolver struct {
	m *manager
}

func (r *dependencyResolver) ResolveSecret(ctx context.Context, ref types.Reference) (types.Secret, error) {
	return r.m.ResolveSecret(ctx, InternalRef(ref.Source, ref.Selector))
}

func (r *dependencyResolver) ResolveCredentials(ctx context.Context, ref types.Reference) (types.Credentials, error) {
	return r.m.ResolveCredentials(ctx, InternalRef(ref.Source, ref.Selector))
}

type secretSource interface {
	Name() string
	DependsOn(evt source.Event) bool
	Dependencies() []types.Reference
	AccessFromRulesAllowed() bool
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	GetSecret(ctx context.Context, selector types.Selector) (types.Secret, error)
	GetSecretSet(ctx context.Context, selector types.Selector) ([]types.Secret, error)
	GetCredentials(ctx context.Context, selector types.Selector) (types.Credentials, error)
}

type managedSource struct {
	s secretSource
	b *binding
}

type manager struct {
	logger     zerolog.Logger
	sources    map[string]*managedSource
	order      []*managedSource
	dispatcher *dispatcher

	mu       sync.RWMutex
	bindings map[bindingKey]*binding
}

func NewManager(
	cfg *config.Configuration,
	logger zerolog.Logger,
	df encoding.DecoderFactory,
) (*manager, error) {
	dispatcher, err := newDispatcher(logger)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed creating secret update dispatcher",
		).CausedBy(err)
	}

	mgr := &manager{
		logger:     logger,
		sources:    make(map[string]*managedSource, len(cfg.SecretManagement)),
		dispatcher: dispatcher,
		bindings:   make(map[bindingKey]*binding, 10),
	}

	if err = mgr.createSources(cfg, df); err != nil {
		dispatcher.stop()

		return nil, err
	}

	if err = mgr.orderSources(); err != nil {
		dispatcher.stop()

		return nil, err
	}

	return mgr, nil
}

func (m *manager) Start(ctx context.Context) error {
	startedSources := make([]*managedSource, 0, len(m.order))

	for _, src := range m.order {
		if err := src.s.Start(ctx); err != nil {
			_ = stopStartedSources(context.Background(), startedSources) //nolint:contextcheck

			return err
		}

		startedSources = append(startedSources, src)
	}

	return nil
}

func (m *manager) Stop(ctx context.Context) error {
	m.mu.Lock()

	bindings := maps.Clone(m.bindings)
	clear(m.bindings)

	m.mu.Unlock()

	for _, bdg := range bindings {
		bdg.stop()
	}

	err := stopStartedSources(ctx, m.order)

	m.dispatcher.stop()

	return err
}

func (m *manager) ResolveSecret(ctx context.Context, reference Reference) (Secret, error) {
	src, err := m.lookupSource(reference)
	if err != nil {
		return nil, err
	}

	return src.GetSecret(ctx, types.Selector{Value: reference.Selector, Namespace: reference.Namespace})
}

func (m *manager) ResolveSecretSet(ctx context.Context, reference Reference) ([]Secret, error) {
	src, err := m.lookupSource(reference)
	if err != nil {
		return nil, err
	}

	return src.GetSecretSet(ctx, types.Selector{Value: reference.Selector, Namespace: reference.Namespace})
}

func (m *manager) ResolveCredentials(ctx context.Context, reference Reference) (Credentials, error) {
	src, err := m.lookupSource(reference)
	if err != nil {
		return nil, err
	}

	return src.GetCredentials(ctx, types.Selector{Value: reference.Selector, Namespace: reference.Namespace})
}

func (m *manager) Subscribe(reference Reference, cb func(context.Context) error) (func(), error) {
	if cb == nil {
		return nil, fmt.Errorf("%w: callback must not be nil", ErrSubscribeFailed)
	}

	if _, err := m.lookupSource(reference); err != nil {
		return nil, err
	}

	key := bindingKey{
		source:    reference.Source,
		selector:  reference.Selector,
		namespace: reference.Namespace,
	}

	bdg := m.getBinding(key)
	subscriberID := bdg.addSubscriber(cb)

	return func() {
		m.mu.Lock()

		bdg := m.bindings[key]
		if bdg == nil {
			m.mu.Unlock()

			return
		}

		if bdg.removeSubscriber(subscriberID) {
			m.mu.Unlock()

			return
		}

		delete(m.bindings, key)
		m.mu.Unlock()

		bdg.stop()
	}, nil
}

func (m *manager) Notify(evt source.Event) {
	bindings := m.matchingBindings(evt)
	dependents := m.matchingProviderDependents(evt)

	for _, bdg := range bindings {
		m.dispatcher.schedule(bdg)
	}

	for _, src := range dependents {
		m.dispatcher.schedule(src.b)
	}
}

func (m *manager) getBinding(key bindingKey) *binding {
	m.mu.Lock()
	defer m.mu.Unlock()

	bdg := m.bindings[key]
	if bdg == nil {
		bdg = newBinding(key, m.logger)
		m.bindings[key] = bdg
	}

	return bdg
}

func (m *manager) lookupSource(reference Reference) (secretSource, error) {
	ms, ok := m.sources[reference.Source]

	if !ok {
		return nil, errorchain.NewWithMessage(ErrSourceNotFound, reference.Source)
	}

	if reference.RuleContext && !ms.s.AccessFromRulesAllowed() {
		return nil, ErrSecretSourceForbidden
	}

	return ms.s, nil
}

func (m *manager) matchingProviderDependents(evt source.Event) []*managedSource {
	dependents := make([]*managedSource, 0, len(m.order))

	for _, src := range m.order {
		if src.s.DependsOn(evt) {
			dependents = append(dependents, src)
		}
	}

	return dependents
}

func (m *manager) matchingBindings(evt source.Event) []*binding {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(evt.Selectors) == 0 {
		bindings := make([]*binding, 0, len(m.bindings))

		for key, bdg := range m.bindings {
			if key.source != evt.Source {
				continue
			}

			bindings = append(bindings, bdg)
		}

		return bindings
	}

	bindings := make([]*binding, 0, len(evt.Selectors))
	for _, selector := range evt.Selectors {
		bdg := m.bindings[bindingKey{
			source:    evt.Source,
			selector:  selector.Value,
			namespace: selector.Namespace,
		}]
		if bdg != nil {
			bindings = append(bindings, bdg)
		}
	}

	return bindings
}

func (m *manager) createSources(cfg *config.Configuration, df encoding.DecoderFactory) error {
	resolver := &dependencyResolver{m: m}

	for sourceName, sourceCfg := range cfg.SecretManagement {
		src, err := source.New(
			sourceName,
			sourceCfg,
			m.logger,
			df,
			m,
			resolver,
		)
		if err != nil {
			return err
		}

		bdg := newBinding(bindingKey{source: sourceName}, m.logger)
		bdg.addSubscriber(func(ctx context.Context) error {
			return m.restart(ctx, src)
		})

		m.sources[sourceName] = &managedSource{
			s: src,
			b: bdg,
		}
	}

	return nil
}

func (m *manager) restart(ctx context.Context, src secretSource) error {
	m.logger.Debug().
		Str("_secret_source", src.Name()).
		Msg("Restarting secret source after dependency change")

	if err := src.Stop(ctx); err != nil {
		return errorchain.NewWithMessagef(
			err,
			"failed stopping secret source '%s' during dependency restart",
			src.Name(),
		)
	}

	if err := src.Start(ctx); err != nil {
		return errorchain.NewWithMessagef(
			err,
			"failed starting secret source '%s' during dependency restart",
			src.Name(),
		)
	}

	m.logger.Debug().
		Str("_secret_source", src.Name()).
		Msg("Secret source restarted after dependency change")

	m.Notify(source.Event{Source: src.Name()})

	return nil
}

func (m *manager) orderSources() error {
	dag := graph.New(
		func(source *managedSource) string { return source.s.Name() },
		graph.Directed(),
		graph.Acyclic(),
		graph.PreventCycles(),
	)

	for name, src := range m.sources {
		if err := dag.AddVertex(src); err != nil {
			return errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"failed adding secret source '%s' to dependency graph", name,
			).CausedBy(err)
		}
	}

	for name, src := range m.sources {
		for _, dep := range src.s.Dependencies() {
			if err := dag.AddEdge(dep.Source, name); err != nil {
				if errors.Is(err, graph.ErrEdgeAlreadyExists) {
					continue
				}

				return errorchain.NewWithMessagef(
					pipeline.ErrConfiguration,
					"invalid secret source dependency '%s' -> '%s'", dep.Source, name,
				).CausedBy(err)
			}
		}
	}

	order, err := graph.TopologicalSort(dag)
	if err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed sorting secret source dependency graph",
		).CausedBy(err)
	}

	m.order = make([]*managedSource, 0, len(order))
	for _, sourceName := range order {
		m.order = append(m.order, m.sources[sourceName])
	}

	return nil
}

func stopStartedSources(ctx context.Context, sources []*managedSource) error {
	var stopErr error

	for idx := len(sources) - 1; idx >= 0; idx-- {
		src := sources[idx]
		src.b.stop()

		if err := src.s.Stop(ctx); err != nil && stopErr == nil {
			stopErr = err
		}
	}

	return stopErr
}
