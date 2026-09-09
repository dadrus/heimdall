// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package requestcoordinator

import "github.com/dadrus/heimdall/internal/pipeline"

type ContextFactory[I any, C pipeline.ExecutionContext] interface {
	Create(input I) C
	Destroy(ctx C)
}

type Committer[T any, C pipeline.ExecutionContext, O any] interface {
	Commit(target T, ctx C) (O, error)
}

type Coordinator[
	I any,
	T any,
	C pipeline.ExecutionContext,
	O any,
] struct {
	executor  pipeline.Executor
	factory   ContextFactory[I, C]
	committer Committer[T, C, O]
}

func New[
	I any,
	T any,
	C pipeline.ExecutionContext,
	O any,
](
	executor pipeline.Executor,
	factory ContextFactory[I, C],
	committer Committer[T, C, O],
) *Coordinator[I, T, C, O] {
	return &Coordinator[I, T, C, O]{
		executor:  executor,
		factory:   factory,
		committer: committer,
	}
}

func (c *Coordinator[I, T, C, O]) Handle(input I, target T) (O, error) {
	ctx := c.factory.Create(input)
	defer c.factory.Destroy(ctx)

	var zero O

	if err := c.executor.Execute(ctx); err != nil {
		return zero, err
	}

	if err := ctx.Error(); err != nil {
		return zero, err
	}

	return c.committer.Commit(target, ctx)
}
