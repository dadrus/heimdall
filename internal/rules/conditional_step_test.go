// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package rules

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/mocks"
	rulemocks "github.com/dadrus/heimdall/internal/rules/mocks"
)

func TestConditionalStepExecute(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		configureMocks func(t *testing.T, ecm *rulemocks.ExecutionConditionMock, sm *mocks.StepMock, cm *mocks.ContextMock)
		assert         func(t *testing.T, err error)
	}{
		"executes if can for non error_handler kind": {
			configureMocks: func(t *testing.T, ecm *rulemocks.ExecutionConditionMock, sm *mocks.StepMock, _ *mocks.ContextMock) {
				t.Helper()

				ecm.EXPECT().CanExecuteOnSubject(mock.Anything, mock.Anything).Return(true, nil)
				sm.EXPECT().Execute(mock.Anything, mock.Anything).Return(nil)
				sm.EXPECT().ID().Return("test")
				sm.EXPECT().Kind().Return(pipeline.KindAuthenticator)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"executes if can for error_handler kind": {
			configureMocks: func(t *testing.T, ecm *rulemocks.ExecutionConditionMock, sm *mocks.StepMock, cm *mocks.ContextMock) {
				t.Helper()

				cm.EXPECT().Error().Return(errors.New("some error"))

				ecm.EXPECT().CanExecuteOnError(mock.Anything, mock.Anything).Return(true, nil)
				sm.EXPECT().Execute(mock.Anything, mock.Anything).Return(nil)
				sm.EXPECT().ID().Return("test")
				sm.EXPECT().Kind().Return(pipeline.KindErrorHandler)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"does not execute if can not on non error_handler kind": {
			configureMocks: func(t *testing.T, ecm *rulemocks.ExecutionConditionMock, sm *mocks.StepMock, _ *mocks.ContextMock) {
				t.Helper()

				ecm.EXPECT().CanExecuteOnSubject(mock.Anything, mock.Anything).Return(false, nil)
				sm.EXPECT().ID().Return("test")
				sm.EXPECT().Kind().Return(pipeline.KindAuthorizer)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"does not execute if can not on error_handler kind": {
			configureMocks: func(t *testing.T, ecm *rulemocks.ExecutionConditionMock, sm *mocks.StepMock, cm *mocks.ContextMock) {
				t.Helper()

				cm.EXPECT().Error().Return(errors.New("some error"))

				ecm.EXPECT().CanExecuteOnError(mock.Anything, mock.Anything).Return(false, nil)
				sm.EXPECT().ID().Return("test")
				sm.EXPECT().Kind().Return(pipeline.KindErrorHandler)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"does not execute if can check fails for non error_handler kind": {
			configureMocks: func(t *testing.T, ecm *rulemocks.ExecutionConditionMock, sm *mocks.StepMock, _ *mocks.ContextMock) {
				t.Helper()

				ecm.EXPECT().CanExecuteOnSubject(mock.Anything, mock.Anything).
					Return(true, errors.New("test error"))
				sm.EXPECT().ID().Return("test")
				sm.EXPECT().Kind().Return(pipeline.KindContextualizer)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"does not execute if can check fails for error_handler kind": {
			configureMocks: func(t *testing.T, ecm *rulemocks.ExecutionConditionMock, sm *mocks.StepMock, cm *mocks.ContextMock) {
				t.Helper()

				cm.EXPECT().Error().Return(errors.New("some error"))

				ecm.EXPECT().CanExecuteOnError(mock.Anything, mock.Anything).
					Return(true, errors.New("test error"))
				sm.EXPECT().ID().Return("test")
				sm.EXPECT().Kind().Return(pipeline.KindErrorHandler)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			condition := rulemocks.NewExecutionConditionMock(t)
			step := mocks.NewStepMock(t)
			decorator := conditionalStep{c: condition, s: step}

			ctx := mocks.NewContextMock(t)
			ctx.EXPECT().Context().Return(t.Context())

			tc.configureMocks(t, condition, step, ctx)

			// WHEN
			err := decorator.Execute(ctx, nil)

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestConditionalStepID(t *testing.T) {
	t.Parallel()

	condition := rulemocks.NewExecutionConditionMock(t)
	step := mocks.NewStepMock(t)
	step.EXPECT().ID().Return("test")

	eh := conditionalStep{c: condition, s: step}

	id := eh.ID()
	assert.Equal(t, "test", id)
}

func TestConditionalStepType(t *testing.T) {
	t.Parallel()

	condition := rulemocks.NewExecutionConditionMock(t)
	step := mocks.NewStepMock(t)
	step.EXPECT().Type().Return("test")

	eh := conditionalStep{c: condition, s: step}

	typ := eh.Type()
	assert.Equal(t, "test", typ)
}

func TestConditionalStepKind(t *testing.T) {
	t.Parallel()

	condition := rulemocks.NewExecutionConditionMock(t)
	step := mocks.NewStepMock(t)
	step.EXPECT().Kind().Return(pipeline.KindAuthenticator)

	eh := conditionalStep{c: condition, s: step}

	kind := eh.Kind()
	assert.Equal(t, pipeline.KindAuthenticator, kind)
}

func TestConditionalStepAccept(t *testing.T) {
	t.Parallel()

	// GIVEN
	visitor := mocks.NewVisitorMock(t)
	condition := rulemocks.NewExecutionConditionMock(t)
	step := mocks.NewStepMock(t)

	step.EXPECT().Accept(visitor)

	cs := &conditionalStep{c: condition, s: step}

	// WHEN
	cs.Accept(visitor)

	// THEN all expecations are met
}
