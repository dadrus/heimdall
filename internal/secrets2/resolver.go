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

package secrets2

import (
	"context"
	"maps"
	"sync"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/secrets2/source"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/task"
)

const bindingRefreshTaskWorkers = 4

type sourceObserverFunc func(source.Event)

func (fn sourceObserverFunc) Notify(evt source.Event) {
	fn(evt)
}

func applyScopeOptions(opts ...ScopeOption) scopeOptions {
	resolved := scopeOptions{}

	for _, opt := range opts {
		if opt != nil {
			opt(&resolved)
		}
	}

	return resolved
}

func applyResolveOptions(opts ...ResolveOption) resolveOptions {
	resolved := resolveOptions{
		mode: ResolveEager,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(&resolved)
		}
	}

	return resolved
}

type resolver struct {
	logger zerolog.Logger

	sources  source.Repository
	executor *task.Executor

	appScope *scope

	scopesMu   sync.Mutex
	ruleScopes map[string]*scope

	mu                        sync.RWMutex
	secretBindings            map[bindingKey]*leasedBinding[Secret]
	secretSetBindings         map[bindingKey]*leasedBinding[[]Secret]
	credentialsBindings       map[bindingKey]*leasedBinding[Credentials]
	certificateBundleBindings map[bindingKey]*leasedBinding[CertificateBundle]
}

func newResolver(
	logger zerolog.Logger,
	sources source.Repository,
) (*resolver, error) {
	executor, err := task.NewExecutor(bindingRefreshTaskWorkers)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			ErrInternal,
			"failed creating secret binding refresh task executor",
		).CausedBy(err)
	}

	res := &resolver{
		logger:                    logger,
		sources:                   sources,
		executor:                  executor,
		ruleScopes:                make(map[string]*scope),
		secretBindings:            make(map[bindingKey]*leasedBinding[Secret]),
		secretSetBindings:         make(map[bindingKey]*leasedBinding[[]Secret]),
		credentialsBindings:       make(map[bindingKey]*leasedBinding[Credentials]),
		certificateBundleBindings: make(map[bindingKey]*leasedBinding[CertificateBundle]),
	}

	res.appScope = newScope(res)

	sources.AddObserver(sourceObserverFunc(res.handleSourceEvent))

	return res, nil
}

func (r *resolver) Resolver() Resolver {
	return r.appScope
}

func (r *resolver) ScopedResolver(id string, opts ...ScopeOption) RuleScopedResolver {
	cfg := applyScopeOptions(opts...)

	r.scopesMu.Lock()
	defer r.scopesMu.Unlock()

	scope := r.ruleScopes[id]
	if scope == nil {
		scope = newScope(r,
			withID(id),
			withReleaser(r),
			withNamespace(cfg.namespace),
		)
		r.ruleScopes[id] = scope
	}

	return scope
}

func (r *resolver) Stop() {
	r.appScope.Release()

	r.scopesMu.Lock()
	ruleScopes := maps.Clone(r.ruleScopes)
	clear(r.ruleScopes)
	r.scopesMu.Unlock()

	for _, scope := range ruleScopes {
		scope.Release()
	}

	r.stopBindings()

	r.executor.Stop()
}

func (r *resolver) ResolveSecret(ctx context.Context, ref Reference) (Secret, error) {
	return r.resolveSecret(ctx, internalRef(ref))
}

func (r *resolver) ResolveCredentials(ctx context.Context, ref Reference) (Credentials, error) {
	return r.resolveCredentials(ctx, internalRef(ref))
}

func (r *resolver) ResolveCertificateBundle(ctx context.Context, ref Reference) (CertificateBundle, error) {
	return r.resolveCertificateBundle(ctx, internalRef(ref))
}

func (r *resolver) secretBinding(
	ctx context.Context,
	reference scopedReference,
	opts ...ResolveOption,
) (*binding[Secret], bindingKey, error) {
	key, err := r.bindingKey(reference, bindingKindSecret)
	if err != nil {
		return nil, bindingKey{}, err
	}

	cfg := applyResolveOptions(opts...)
	created := false

	r.mu.Lock()

	entry := r.secretBindings[key]
	if entry == nil {
		ref := reference
		bdg := newBinding(key, r.logger, func(ctx context.Context) (Secret, error) {
			return r.resolveSecret(ctx, ref)
		})

		entry = newLeasedBinding(bdg)
		r.secretBindings[key] = entry
		created = true
	}

	entry.leases++
	bdg := entry.binding

	r.mu.Unlock()

	if created || cfg.mode == ResolveEager {
		if err = entry.resolveInitial(ctx, r.executor, cfg.mode); err != nil {
			r.releaseBinding(key, 1)

			return nil, bindingKey{}, err
		}
	}

	return bdg, key, nil
}

func (r *resolver) secretSetBinding(
	ctx context.Context,
	reference scopedReference,
	opts ...ResolveOption,
) (*binding[[]Secret], bindingKey, error) {
	key, err := r.bindingKey(reference, bindingKindSecretSet)
	if err != nil {
		return nil, bindingKey{}, err
	}

	cfg := applyResolveOptions(opts...)
	created := false

	r.mu.Lock()

	entry := r.secretSetBindings[key]
	if entry == nil {
		ref := reference
		bdg := newBinding(key, r.logger, func(ctx context.Context) ([]Secret, error) {
			return r.resolveSecretSet(ctx, ref)
		})

		entry = newLeasedBinding(bdg)
		r.secretSetBindings[key] = entry
		created = true
	}

	entry.leases++
	bdg := entry.binding

	r.mu.Unlock()

	if created || cfg.mode == ResolveEager {
		if err = entry.resolveInitial(ctx, r.executor, cfg.mode); err != nil {
			r.releaseBinding(key, 1)

			return nil, bindingKey{}, err
		}
	}

	return bdg, key, nil
}

func (r *resolver) credentialsBinding(
	ctx context.Context,
	reference scopedReference,
	opts ...ResolveOption,
) (*binding[Credentials], bindingKey, error) {
	key, err := r.bindingKey(reference, bindingKindCredentials)
	if err != nil {
		return nil, bindingKey{}, err
	}

	cfg := applyResolveOptions(opts...)
	created := false

	r.mu.Lock()

	entry := r.credentialsBindings[key]
	if entry == nil {
		ref := reference
		bdg := newBinding(key, r.logger, func(ctx context.Context) (Credentials, error) {
			return r.resolveCredentials(ctx, ref)
		})

		entry = newLeasedBinding(bdg)
		r.credentialsBindings[key] = entry
		created = true
	}

	entry.leases++
	bdg := entry.binding

	r.mu.Unlock()

	if created || cfg.mode == ResolveEager {
		if err = entry.resolveInitial(ctx, r.executor, cfg.mode); err != nil {
			r.releaseBinding(key, 1)

			return nil, bindingKey{}, err
		}
	}

	return bdg, key, nil
}

func (r *resolver) certificateBundleBinding(
	ctx context.Context,
	reference scopedReference,
	opts ...ResolveOption,
) (*binding[CertificateBundle], bindingKey, error) {
	key, err := r.bindingKey(reference, bindingKindCertificateBundle)
	if err != nil {
		return nil, bindingKey{}, err
	}

	cfg := applyResolveOptions(opts...)
	created := false

	r.mu.Lock()

	entry := r.certificateBundleBindings[key]
	if entry == nil {
		ref := reference
		bdg := newBinding(key, r.logger, func(ctx context.Context) (CertificateBundle, error) {
			return r.resolveCertificateBundle(ctx, ref)
		})

		entry = newLeasedBinding(bdg)
		r.certificateBundleBindings[key] = entry
		created = true
	}

	entry.leases++
	bdg := entry.binding

	r.mu.Unlock()

	if created || cfg.mode == ResolveEager {
		if err = entry.resolveInitial(ctx, r.executor, cfg.mode); err != nil {
			r.releaseBinding(key, 1)

			return nil, bindingKey{}, err
		}
	}

	return bdg, key, nil
}

func (r *resolver) releaseBinding(key bindingKey, count int) {
	switch key.kind {
	case bindingKindSecret:
		releaseBinding(r, r.secretBindings, key, count)
	case bindingKindSecretSet:
		releaseBinding(r, r.secretSetBindings, key, count)
	case bindingKindCredentials:
		releaseBinding(r, r.credentialsBindings, key, count)
	case bindingKindCertificateBundle:
		releaseBinding(r, r.certificateBundleBindings, key, count)
	}
}

func releaseBinding[T any](
	resolver *resolver,
	bindings map[bindingKey]*leasedBinding[T],
	key bindingKey,
	count int,
) {
	var toStop *leasedBinding[T]

	resolver.mu.Lock()

	entry := bindings[key]
	if entry != nil {
		entry.leases -= count
		if entry.leases <= 0 {
			delete(bindings, key)

			toStop = entry
		}
	}

	resolver.mu.Unlock()

	if toStop != nil {
		toStop.stop()
	}
}

func (r *resolver) resolveSecret(ctx context.Context, ref scopedReference) (Secret, error) {
	src, err := r.lookupSource(ref)
	if err != nil {
		return nil, err
	}

	return src.GetSecret(ctx, selectorFor(src, ref))
}

func (r *resolver) resolveSecretSet(ctx context.Context, ref scopedReference) ([]Secret, error) {
	src, err := r.lookupSource(ref)
	if err != nil {
		return nil, err
	}

	return src.GetSecretSet(ctx, selectorFor(src, ref))
}

func (r *resolver) resolveCredentials(ctx context.Context, ref scopedReference) (Credentials, error) {
	src, err := r.lookupSource(ref)
	if err != nil {
		return nil, err
	}

	return src.GetCredentials(ctx, selectorFor(src, ref))
}

func (r *resolver) resolveCertificateBundle(ctx context.Context, ref scopedReference) (CertificateBundle, error) {
	src, err := r.lookupSource(ref)
	if err != nil {
		return nil, err
	}

	return src.GetCertificateBundle(ctx, selectorFor(src, ref))
}

func (r *resolver) bindingKey(reference scopedReference, kind bindingKind) (bindingKey, error) {
	src, err := r.lookupSource(reference)
	if err != nil {
		return bindingKey{}, err
	}

	namespace := ""
	if src.IsNamespaceAware() {
		namespace = reference.namespace
	}

	return bindingKey{
		kind:      kind,
		source:    reference.Source,
		selector:  reference.Selector,
		namespace: namespace,
		scope:     reference.scope,
	}, nil
}

func (r *resolver) lookupSource(reference scopedReference) (source.Source, error) {
	src, err := r.sources.Lookup(reference.Source)
	if err != nil {
		return nil, err
	}

	if reference.scope == referenceScopeRule && !src.AccessFromRulesAllowed() {
		return nil, ErrSourceForbidden
	}

	return src, nil
}

func (r *resolver) handleSourceEvent(evt source.Event) {
	for _, tsk := range r.match(evt) {
		r.executor.Schedule(tsk)
	}
}

func (r *resolver) match(evt source.Event) []task.Task {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tasks := make([]task.Task, 0)

	var namespaceAware bool

	src, err := r.sources.Lookup(evt.Source)
	if err == nil {
		namespaceAware = src.IsNamespaceAware()
	}

	matches := func(key bindingKey) bool {
		if key.source != evt.Source {
			return false
		}

		if len(evt.Selectors) == 0 {
			return true
		}

		for _, selector := range evt.Selectors {
			namespace := ""
			if namespaceAware {
				namespace = selector.Namespace
			}

			if key.selector == selector.Value && key.namespace == namespace {
				return true
			}
		}

		return false
	}

	for key, entry := range r.secretBindings {
		if matches(key) {
			tasks = append(tasks, entry.binding)
		}
	}

	for key, entry := range r.secretSetBindings {
		if matches(key) {
			tasks = append(tasks, entry.binding)
		}
	}

	for key, entry := range r.credentialsBindings {
		if matches(key) {
			tasks = append(tasks, entry.binding)
		}
	}

	for key, entry := range r.certificateBundleBindings {
		if matches(key) {
			tasks = append(tasks, entry.binding)
		}
	}

	return tasks
}

func (r *resolver) releaseScope(id string, scope *scope) {
	r.scopesMu.Lock()
	defer r.scopesMu.Unlock()

	if r.ruleScopes[id] == scope {
		delete(r.ruleScopes, id)
	}
}

func (r *resolver) stopBindings() {
	r.mu.Lock()

	secretBindings := maps.Clone(r.secretBindings)
	secretSetBindings := maps.Clone(r.secretSetBindings)
	credentialsBindings := maps.Clone(r.credentialsBindings)
	certificateBundleBindings := maps.Clone(r.certificateBundleBindings)

	clear(r.secretBindings)
	clear(r.secretSetBindings)
	clear(r.credentialsBindings)
	clear(r.certificateBundleBindings)

	r.mu.Unlock()

	for _, entry := range secretBindings {
		entry.stop()
	}

	for _, entry := range secretSetBindings {
		entry.stop()
	}

	for _, entry := range credentialsBindings {
		entry.stop()
	}

	for _, entry := range certificateBundleBindings {
		entry.stop()
	}
}

func selectorFor(src source.Source, reference scopedReference) source.Selector {
	selector := source.Selector{
		Value: reference.Selector,
	}

	if src.IsNamespaceAware() {
		selector.Namespace = reference.namespace
	}

	return selector
}

var (
	_ Resolvers                   = (*resolver)(nil)
	_ source.DependenciesResolver = (*resolver)(nil)
	_ bindingProvider             = (*resolver)(nil)
	_ scopeReleaser               = (*resolver)(nil)
)
