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
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog"
	"golang.org/x/sync/singleflight"

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

type binding[T any] struct {
	task.StateMachine
	bindingKey

	logger  zerolog.Logger
	resolve func(context.Context) (T, error)

	value atomic.Value // stores T

	resolveGroup singleflight.Group

	callbacksMu      sync.RWMutex
	nextSubscriberID uint64
	callbacks        map[uint64]UpdateFunc[T]
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
	resolve func(context.Context) (T, error),
) *binding[T] {
	return &binding[T]{
		bindingKey: bk,
		logger:     logger,
		resolve:    resolve,
		callbacks:  make(map[uint64]UpdateFunc[T]),
	}
}

func (b *binding[T]) get(ctx context.Context) (T, bool) {
	if value, ok := b.peek(); ok {
		return value, true
	}

	value, err := b.resolveOnce(ctx, resolveGroupCached)
	if err != nil {
		var zero T

		return zero, false
	}

	return value, true
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

			return zero, err
		}

		b.publish(value)

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
		b.runCallback(cb, value)
	}

	return func() {
		b.callbacksMu.Lock()
		defer b.callbacksMu.Unlock()

		delete(b.callbacks, id)
	}
}

func (b *binding[T]) publish(value T) {
	b.callbacksMu.RLock()

	b.value.Store(value)

	callbacks := make([]UpdateFunc[T], 0, len(b.callbacks))
	for _, cb := range b.callbacks {
		callbacks = append(callbacks, cb)
	}

	b.callbacksMu.RUnlock()

	b.runCallbacks(value, callbacks)
}

func (b *binding[T]) peek() (T, bool) {
	value, ok := b.value.Load().(T)

	return value, ok
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

	b.callbacksMu.Lock()
	defer b.callbacksMu.Unlock()

	clear(b.callbacks)
}

func (b *binding[T]) runCallbacks(value T, callbacks []UpdateFunc[T]) {
	for _, cb := range callbacks {
		b.runCallback(cb, value)
	}
}

func (b *binding[T]) runCallback(cb UpdateFunc[T], value T) {
	if err := cb(context.Background(), value); err != nil {
		b.log(err, "Secret binding update callback failed")
	}
}

var _ task.Task = (*binding[Secret])(nil)
