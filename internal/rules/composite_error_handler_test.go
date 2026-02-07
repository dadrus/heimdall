// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
	"github.com/dadrus/heimdall/internal/x"
)

func TestCompositeErrorHandlerExecute(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setupMocks   func(t *testing.T, ctx *mocks.ContextMock)
		errorHandler func(t *testing.T, ctx heimdall.Context, sub identity.Subject) *compositeErrorHandler
		assert       func(t *testing.T, err error)
	}{
		"with fallback": {
			errorHandler: func(t *testing.T, ctx heimdall.Context, sub identity.Subject) *compositeErrorHandler {
				t.Helper()

				eh1 := mocks.NewStepMock(t)
				eh1.EXPECT().Execute(ctx, sub).Return(errErrorHandlerNotApplicable)

				eh2 := mocks.NewStepMock(t)
				eh2.EXPECT().Execute(ctx, sub).Return(nil)

				return &compositeErrorHandler{eh1, eh2}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"without fallback": {
			errorHandler: func(t *testing.T, ctx heimdall.Context, sub identity.Subject) *compositeErrorHandler {
				t.Helper()

				eh1 := mocks.NewStepMock(t)
				eh1.EXPECT().Execute(ctx, sub).Return(nil)

				eh2 := mocks.NewStepMock(t)

				return &compositeErrorHandler{eh1, eh2}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with no applicable error handler": {
			setupMocks: func(t *testing.T, ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Error().Return(errors.New("test context error"))
			},
			errorHandler: func(t *testing.T, ctx heimdall.Context, sub identity.Subject) *compositeErrorHandler {
				t.Helper()

				eh1 := mocks.NewStepMock(t)
				eh1.EXPECT().Execute(ctx, sub).Return(errErrorHandlerNotApplicable)

				eh2 := mocks.NewStepMock(t)
				eh2.EXPECT().Execute(ctx, sub).Return(errErrorHandlerNotApplicable)

				return &compositeErrorHandler{eh1, eh2}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test context error")
			},
		},
		"error handler fails executing": {
			errorHandler: func(t *testing.T, ctx heimdall.Context, sub identity.Subject) *compositeErrorHandler {
				t.Helper()

				eh1 := mocks.NewStepMock(t)
				eh1.EXPECT().Execute(ctx, sub).Return(errors.New("test execution error"))

				return &compositeErrorHandler{eh1}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test execution error")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			setup := x.IfThenElse(
				tc.setupMocks != nil,
				tc.setupMocks,
				func(t *testing.T, _ *mocks.ContextMock) { t.Helper() },
			)

			sub := identity.Subject{}

			ctx := mocks.NewContextMock(t)
			ctx.EXPECT().Context().Return(t.Context())

			setup(t, ctx)

			eh := tc.errorHandler(t, ctx, sub)

			// WHEN
			err := eh.Execute(ctx, sub)

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestCompositeErrorHandlerAccept(t *testing.T) {
	t.Parallel()

	// GIVEN
	visitor := mocks.NewVisitorMock(t)

	eh1 := mocks.NewStepMock(t)
	eh1.EXPECT().Accept(visitor)

	eh2 := mocks.NewStepMock(t)
	eh2.EXPECT().Accept(visitor)

	eh := &compositeErrorHandler{eh1, eh2}

	// WHEN
	eh.Accept(visitor)

	// THEN all expecations are met
}
