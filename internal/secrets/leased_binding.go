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

	"github.com/dadrus/heimdall/internal/x/task"
)

type leasedBinding[T any] struct {
	task.StateMachine

	binding *binding[T]
	leases  int
}

func newLeasedBinding[T any](binding *binding[T]) *leasedBinding[T] {
	return &leasedBinding[T]{
		binding: binding,
	}
}

func (e *leasedBinding[T]) resolveInitial(
	ctx context.Context,
	executor *task.Executor,
	mode ResolveMode,
) error {
	if mode == ResolveLazy {
		executor.Schedule(e)

		return nil
	}

	_, err := e.binding.resolveOnce(ctx, resolveGroupCached)

	return err
}

func (e *leasedBinding[T]) Unschedule(reason error) {
	e.CancelSchedule()

	if reason != nil {
		e.binding.logger.Warn().
			Err(reason).
			Str("_source", e.binding.source).
			Str("_namespace", e.binding.namespace).
			Str("_selector", e.binding.selector).
			Msg("Failed scheduling initial secret binding resolve task")
	}
}

func (e *leasedBinding[T]) Run() {
	if _, err := e.binding.resolveOnce(context.Background(), resolveGroupCached); err != nil {
		e.binding.logger.Warn().
			Err(err).
			Str("_source", e.binding.source).
			Str("_namespace", e.binding.namespace).
			Str("_selector", e.binding.selector).
			Msg("Failed resolving secret binding")
	}
}

func (e *leasedBinding[T]) stop() {
	e.Stop()
	e.binding.stop()
}

var _ task.Task = (*leasedBinding[Secret])(nil)
