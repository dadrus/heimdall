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

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pipelinemocks "github.com/dadrus/heimdall/internal/pipeline/mocks"
)

type testInput struct {
	value string
}

type testTarget struct {
	value string
}

type testOutput struct {
	value string
}

type testContextFactory struct {
	ctx *pipelinemocks.ExecutionContextMock

	createdWith  testInput
	destroyedCtx *pipelinemocks.ExecutionContextMock
	createCalls  int
	destroyCalls int
}

func (f *testContextFactory) Create(
	input testInput,
) *pipelinemocks.ExecutionContextMock {
	f.createCalls++
	f.createdWith = input

	return f.ctx
}

func (f *testContextFactory) Destroy(
	ctx *pipelinemocks.ExecutionContextMock,
) {
	f.destroyCalls++
	f.destroyedCtx = ctx
}

type testCommitter struct {
	output testOutput
	err    error

	target testTarget
	ctx    *pipelinemocks.ExecutionContextMock
	calls  int
}

func (c *testCommitter) Commit(target testTarget, ctx *pipelinemocks.ExecutionContextMock) (testOutput, error) {
	c.calls++
	c.target = target
	c.ctx = ctx

	return c.output, c.err
}

func TestCoordinatorHandle(t *testing.T) {
	t.Parallel()

	var (
		executionErr = errors.New("execution failed")
		contextErr   = errors.New("context contains an error")
		commitErr    = errors.New("commit failed")

		input  = testInput{value: "input"}
		target = testTarget{value: "target"}
		output = testOutput{value: "output"}
	)

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, executor *pipelinemocks.ExecutorMock, ctx *pipelinemocks.ExecutionContextMock, committer *testCommitter)
		assert func(t *testing.T, result testOutput, err error, committer *testCommitter)
	}{
		"returns execution error": {
			setup: func(t *testing.T, executor *pipelinemocks.ExecutorMock, ctx *pipelinemocks.ExecutionContextMock, _ *testCommitter) {
				t.Helper()

				executor.EXPECT().Execute(ctx).Return(executionErr)
			},
			assert: func(t *testing.T, result testOutput, err error, committer *testCommitter) {
				t.Helper()

				require.ErrorIs(t, err, executionErr)
				assert.Empty(t, result)
				assert.Zero(t, committer.calls)
			},
		},
		"returns context error": {
			setup: func(t *testing.T, executor *pipelinemocks.ExecutorMock, ctx *pipelinemocks.ExecutionContextMock, _ *testCommitter) {
				t.Helper()

				executor.EXPECT().Execute(ctx).Return(nil)
				ctx.EXPECT().Error().Return(contextErr)
			},
			assert: func(t *testing.T, result testOutput, err error, committer *testCommitter) {
				t.Helper()

				require.ErrorIs(t, err, contextErr)
				assert.Empty(t, result)
				assert.Zero(t, committer.calls)
			},
		},
		"commits successful execution": {
			setup: func(t *testing.T, executor *pipelinemocks.ExecutorMock, ctx *pipelinemocks.ExecutionContextMock, committer *testCommitter) {
				t.Helper()

				executor.EXPECT().Execute(ctx).Return(nil)
				ctx.EXPECT().Error().Return(nil)

				committer.output = output
			},
			assert: func(t *testing.T, result testOutput, err error, committer *testCommitter) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, output, result)
				assert.Equal(t, 1, committer.calls)
				assert.Equal(t, target, committer.target)
				assert.NotNil(t, committer.ctx)
			},
		},
		"returns commit error": {
			setup: func(t *testing.T, executor *pipelinemocks.ExecutorMock, ctx *pipelinemocks.ExecutionContextMock, committer *testCommitter) {
				t.Helper()

				executor.EXPECT().Execute(ctx).Return(nil)
				ctx.EXPECT().Error().Return(nil)

				committer.output = output
				committer.err = commitErr
			},
			assert: func(t *testing.T, result testOutput, err error, committer *testCommitter) {
				t.Helper()

				require.ErrorIs(t, err, commitErr)
				assert.Equal(t, output, result)
				assert.Equal(t, 1, committer.calls)
				assert.Equal(t, target, committer.target)
				assert.NotNil(t, committer.ctx)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			ctx := pipelinemocks.NewExecutionContextMock(t)
			executor := pipelinemocks.NewExecutorMock(t)

			factory := &testContextFactory{ctx: ctx}
			committer := &testCommitter{}

			tc.setup(t, executor, ctx, committer)

			coordinator := New(executor, factory, committer)

			result, err := coordinator.Handle(input, target)

			tc.assert(t, result, err, committer)

			assert.Equal(t, 1, factory.createCalls)
			assert.Equal(t, input, factory.createdWith)
			assert.Equal(t, 1, factory.destroyCalls)
			assert.Same(t, ctx, factory.destroyedCtx)
		})
	}
}
