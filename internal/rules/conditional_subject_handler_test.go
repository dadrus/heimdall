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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	rulemocks "github.com/dadrus/heimdall/internal/rules/mocks"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestConditionalSubjectHandlerExecute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		configureMocks func(t *testing.T, c *rulemocks.ExecutionConditionMock, h *rulemocks.SubjectHandlerMock)
		assert         func(t *testing.T, err error)
	}{
		{
			uc: "executes if can",
			configureMocks: func(t *testing.T, c *rulemocks.ExecutionConditionMock, h *rulemocks.SubjectHandlerMock) {
				t.Helper()

				c.EXPECT().CanExecute(mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
				h.EXPECT().Execute(mock.Anything, mock.Anything).Return(nil)
				h.EXPECT().ID().Return("test")
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "does not execute if can not",
			configureMocks: func(t *testing.T, c *rulemocks.ExecutionConditionMock, h *rulemocks.SubjectHandlerMock) {
				t.Helper()

				c.EXPECT().CanExecute(mock.Anything, mock.Anything, mock.Anything).Return(false, nil)
				h.EXPECT().ID().Return("test")
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "does not execute if can check fails",
			configureMocks: func(t *testing.T, c *rulemocks.ExecutionConditionMock, h *rulemocks.SubjectHandlerMock) {
				t.Helper()

				c.EXPECT().CanExecute(mock.Anything, mock.Anything, mock.Anything).
					Return(true, testsupport.ErrTestPurpose)
				h.EXPECT().ID().Return("test")
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, testsupport.ErrTestPurpose)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			condition := rulemocks.NewExecutionConditionMock(t)
			handler := rulemocks.NewSubjectHandlerMock(t)
			decorator := conditionalSubjectHandler{c: condition, h: handler}

			ctx := mocks.NewContextMock(t)
			ctx.EXPECT().AppContext().Return(context.Background())

			tc.configureMocks(t, condition, handler)

			// WHEN
			err := decorator.Execute(ctx, nil)

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestConditionalSubjectHandlerContinueOnError(t *testing.T) {
	t.Parallel()

	// GIVEN
	handler := rulemocks.NewSubjectHandlerMock(t)
	decorator := conditionalSubjectHandler{c: nil, h: handler}

	handler.EXPECT().ContinueOnError().Return(true)

	// WHEN
	ok := decorator.ContinueOnError()

	// THEN
	assert.True(t, ok)
}
