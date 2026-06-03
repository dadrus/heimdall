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
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog"
	"golang.org/x/sync/singleflight"

	"github.com/dadrus/heimdall/internal/secrets/metrics"
	"github.com/dadrus/heimdall/internal/x/task"
)

type resolveGroupKey string

const (
	resolveGroupCached resolveGroupKey = "cached"
	resolveGroupForced resolveGroupKey = "forced"
)

type bindingKind string

const (
	bindingKindSecret            bindingKind = "secret"
	bindingKindSecretSet         bindingKind = "secret_set"
	bindingKindCredentials       bindingKind = "credentials"
	bindingKindCertificateBundle bindingKind = "certificate_bundle"
)

type bindingKey struct {
	kind      bindingKind
	source    string
	selector  string
	namespace string
	scope     referenceScope
}

type storedError struct {
	err error
}

type binding[T any] struct {
	task.StateMachine
	bindingKey

	usage   metrics.SecretUsage
	logger  zerolog.Logger
	resolve func(context.Context) (T, error)

	value   atomic.Value                // stores T
	lastErr atomic.Pointer[storedError] // stores last error

	resolveGroup singleflight.Group

	callbacksMu      sync.RWMutex
	nextSubscriberID uint64
	callbacks        map[uint64]UpdateFunc[T]

	readyOnce sync.Once
	readyCh   chan struct{}
}

func (b *binding[T]) log(err error, msg string) {
	b.logger.Warn().
		Err(err).
		Str("_source", b.source).
		Str("_namespace", b.namespace).
		Str("_selector", b.selector).
		Msg(msg)
}

func newBinding[T any](
	bk bindingKey,
	logger zerolog.Logger,
	usage metrics.SecretUsage,
	resolve func(context.Context) (T, error),
) *binding[T] {
	return &binding[T]{
		bindingKey: bk,
		usage:      usage,
		logger:     logger,
		resolve:    resolve,
		callbacks:  make(map[uint64]UpdateFunc[T]),
		readyCh:    make(chan struct{}),
	}
}

func (b *binding[T]) refresh(ctx context.Context) error {
	_, err := b.resolveOnce(ctx, resolveGroupForced)

	return err
}

func (b *binding[T]) resolveOnce(ctx context.Context, groupKey resolveGroupKey) (T, error) {
	if groupKey == resolveGroupCached {
		if value, ok := b.peek(); ok {
			return value, nil
		}
	}

	ch := b.resolveGroup.DoChan(string(groupKey), func() (any, error) {
		if groupKey == resolveGroupCached {
			if value, ok := b.peek(); ok {
				return value, nil
			}
		}

		value, err := b.resolve(ctx)
		if err != nil {
			var zero T

			b.setLastErr(err)

			return zero, err
		}

		b.publish(ctx, value)

		return value, nil
	})

	select {
	case result := <-ch:
		if result.Err != nil {
			var zero T

			return zero, result.Err
		}

		return result.Val.(T), nil //nolint: forcetypeassert

	case <-ctx.Done():
		var zero T

		return zero, ctx.Err()
	}
}

func (b *binding[T]) subscribe(cb UpdateFunc[T]) func() {
	if cb == nil {
		return func() {}
	}

	b.callbacksMu.Lock()

	b.nextSubscriberID++

	id := b.nextSubscriberID
	b.callbacks[id] = cb

	value, ok := b.peek()

	b.callbacksMu.Unlock()

	if ok {
		b.runCallback(context.Background(), cb, value)
	}

	return func() {
		b.callbacksMu.Lock()
		defer b.callbacksMu.Unlock()

		delete(b.callbacks, id)
	}
}

func (b *binding[T]) publish(ctx context.Context, value T) {
	b.track(value)

	if old, ok := b.peek(); ok {
		b.untrack(old)
	}

	b.value.Store(value)
	b.setLastErr(nil)

	b.readyOnce.Do(func() {
		close(b.readyCh)
	})

	b.callbacksMu.RLock()

	callbacks := make([]UpdateFunc[T], 0, len(b.callbacks))
	for _, cb := range b.callbacks {
		callbacks = append(callbacks, cb)
	}

	b.callbacksMu.RUnlock()

	b.runCallbacks(ctx, value, callbacks)
}

func (b *binding[T]) peek() (T, bool) {
	value, ok := b.value.Load().(T)

	return value, ok
}

func (b *binding[T]) awaitReady(ctx context.Context) error {
	select {
	case <-b.readyCh:
		return nil
	default:
	}

	select {
	case <-b.readyCh:
		return nil

	case <-ctx.Done():
		if err := b.getLastErr(); err != nil {
			return err
		}

		return ctx.Err()
	}
}

func (b *binding[T]) Unschedule(reason error) {
	b.CancelSchedule()

	if reason != nil {
		b.log(reason, "Failed scheduling secret binding refresh task")
	}
}

func (b *binding[T]) Run() {
	if err := b.refresh(context.Background()); err != nil {
		b.log(err, "Failed refreshing secret binding")
	}
}

func (b *binding[T]) stop() {
	b.Stop()

	if value, ok := b.peek(); ok {
		b.untrack(value)
	}

	b.callbacksMu.Lock()
	defer b.callbacksMu.Unlock()

	clear(b.callbacks)
}

func (b *binding[T]) runCallbacks(ctx context.Context, value T, callbacks []UpdateFunc[T]) {
	for _, cb := range callbacks {
		b.runCallback(ctx, cb, value)
	}
}

func (b *binding[T]) runCallback(ctx context.Context, cb UpdateFunc[T], value T) {
	if err := cb(ctx, value); err != nil {
		b.log(err, "Secret binding update callback failed")
	}
}

func (b *binding[T]) setLastErr(err error) {
	if err == nil {
		b.lastErr.Store(nil)

		return
	}

	b.lastErr.Store(&storedError{err: err})
}

func (b *binding[T]) getLastErr() error {
	stored := b.lastErr.Load()
	if stored == nil {
		return nil
	}

	return stored.err
}

func (b *binding[T]) track(value T) {
	secret, ok := any(value).(Secret)
	if !ok || secret == nil {
		return
	}

	b.usage.Track(secret)
}

func (b *binding[T]) untrack(value T) {
	secret, ok := any(value).(Secret)
	if !ok || secret == nil {
		return
	}

	b.usage.Untrack(secret)
}

var _ task.Task = (*binding[Secret])(nil)
