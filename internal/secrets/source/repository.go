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

package source

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/dominikbraun/graph"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/task"
)

type repositoryObserver struct {
	r *repositoryImpl
}

func (o *repositoryObserver) Notify(evt Event) {
	o.r.handleEvent(evt)
}

type Repository interface {
	AddObserver(observer Observer)
	Lookup(sourceName string) (Source, error)

	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

type sourceList []*secretSource

func (s sourceList) lookup(name string) (*secretSource, error) {
	for _, src := range s {
		if src.Name() == name {
			return src, nil
		}
	}

	return nil, errorchain.NewWithMessage(types.ErrSourceNotFound, name)
}

func (s sourceList) start(ctx context.Context) error {
	started := make(sourceList, 0, len(s))

	for _, src := range s {
		if err := src.Start(ctx); err != nil {
			_ = started.shutdown(context.Background()) //nolint:contextcheck

			return err
		}

		started = append(started, src)
	}

	return nil
}

func (s sourceList) shutdown(ctx context.Context) error {
	var stopErr error

	for idx := len(s) - 1; idx >= 0; idx-- {
		src := s[idx]
		src.stopTask()

		if err := src.Stop(ctx); err != nil && stopErr == nil {
			stopErr = err
		}
	}

	return stopErr
}

type repositoryImpl struct {
	logger zerolog.Logger

	sources sourceList

	executor *task.Executor

	observersMu sync.RWMutex
	observers   []Observer
}

func NewRepository(
	cfg *config.Configuration,
	logger zerolog.Logger,
	df encoding.DecoderFactory,
	resolver DependenciesResolver,
) (Repository, error) {
	const numberOfWorkers = 4

	executor, err := task.NewExecutor(numberOfWorkers) //nolint:mnd
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrInternal,
			"failed creating source restart task executor",
		).CausedBy(err)
	}

	registry := &repositoryImpl{logger: logger, executor: executor}
	observer := &repositoryObserver{r: registry}
	srcs := make(map[string]*secretSource, len(cfg.SecretManagement))

	for sourceName, sourceCfg := range cfg.SecretManagement {
		src, err := newSecretSource(
			sourceName,
			sourceCfg,
			logger,
			df,
			observer,
			resolver,
		)
		if err != nil {
			executor.Stop()

			return nil, err
		}

		srcs[sourceName] = src
	}

	registry.sources, err = orderSources(srcs)
	if err != nil {
		executor.Stop()

		return nil, err
	}

	return registry, nil
}

func (r *repositoryImpl) AddObserver(observer Observer) {
	if observer == nil {
		return
	}

	r.observersMu.Lock()
	defer r.observersMu.Unlock()

	r.observers = append(r.observers, observer)
}

func (r *repositoryImpl) Start(ctx context.Context) error {
	return r.sources.start(ctx)
}

func (r *repositoryImpl) Stop(ctx context.Context) error {
	err := r.sources.shutdown(ctx)

	r.executor.Stop()

	return err
}

func (r *repositoryImpl) Lookup(sourceName string) (Source, error) {
	return r.sources.lookup(sourceName)
}

func (r *repositoryImpl) handleEvent(evt Event) {
	for _, src := range r.sources {
		if src.DependsOn(evt) {
			r.executor.Schedule(src)
		}
	}

	r.notifyObservers(evt)
}

func (r *repositoryImpl) notifyObservers(evt Event) {
	r.observersMu.RLock()
	observers := slices.Clone(r.observers)
	r.observersMu.RUnlock()

	for _, observer := range observers {
		observer.Notify(evt)
	}
}

func orderSources(srcs map[string]*secretSource) (sourceList, error) {
	dag := graph.New(
		func(src *secretSource) string { return src.Name() },
		graph.Directed(),
		graph.Acyclic(),
		graph.PreventCycles(),
	)

	for name, src := range srcs {
		if err := dag.AddVertex(src); err != nil {
			return nil, errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"failed adding secret source '%s' to dependency graph", name,
			).CausedBy(err)
		}
	}

	for name, src := range srcs {
		for _, dep := range src.Dependencies() {
			if err := dag.AddEdge(dep.Source, name); err != nil {
				if errors.Is(err, graph.ErrEdgeAlreadyExists) {
					continue
				}

				return nil, errorchain.NewWithMessagef(
					pipeline.ErrConfiguration,
					"invalid secret source dependency '%s' -> '%s'", dep.Source, name,
				).CausedBy(err)
			}
		}
	}

	order, err := graph.TopologicalSort(dag)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed sorting secret source dependency graph",
		).CausedBy(err)
	}

	ordered := make([]*secretSource, 0, len(order))
	for _, sourceName := range order {
		ordered = append(ordered, srcs[sourceName])
	}

	return ordered, nil
}

var _ Repository = (*repositoryImpl)(nil)
