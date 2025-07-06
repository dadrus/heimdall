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
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	rulemocks "github.com/dadrus/heimdall/internal/rules/mocks"
)

func TestCompositeSubjectHandlerExecution(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		configureMocks func(t *testing.T, ctx heimdall.RequestContext, first *rulemocks.SubjectHandlerMock,
			second *rulemocks.SubjectHandlerMock, sub *subject.Subject)
		assert func(t *testing.T, err error)
	}{
		"all succeeded": {
			configureMocks: func(t *testing.T, ctx heimdall.RequestContext, first *rulemocks.SubjectHandlerMock,
				second *rulemocks.SubjectHandlerMock, sub *subject.Subject,
			) {
				t.Helper()

				first.EXPECT().Execute(ctx, sub).Return(nil)
				second.EXPECT().Execute(ctx, sub).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"first fails without pipeline continuation": {
			configureMocks: func(t *testing.T, ctx heimdall.RequestContext, first *rulemocks.SubjectHandlerMock,
				_ *rulemocks.SubjectHandlerMock, sub *subject.Subject,
			) {
				t.Helper()

				first.EXPECT().Execute(ctx, sub).Return(errors.New("first fails"))
				first.EXPECT().ContinueOnError().Return(false)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, "first fails", err.Error())
			},
		},
		"first fails with pipeline continuation, second succeeds": {
			configureMocks: func(t *testing.T, ctx heimdall.RequestContext, first *rulemocks.SubjectHandlerMock,
				second *rulemocks.SubjectHandlerMock, sub *subject.Subject,
			) {
				t.Helper()

				first.EXPECT().Execute(ctx, sub).Return(errors.New("first fails"))
				first.EXPECT().ContinueOnError().Return(true)
				second.EXPECT().Execute(ctx, sub).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"second fails without pipeline continuation": {
			configureMocks: func(t *testing.T, ctx heimdall.RequestContext, first *rulemocks.SubjectHandlerMock,
				second *rulemocks.SubjectHandlerMock, sub *subject.Subject,
			) {
				t.Helper()

				first.EXPECT().Execute(ctx, sub).Return(nil)
				second.EXPECT().Execute(ctx, sub).Return(errors.New("second fails"))
				second.EXPECT().ContinueOnError().Return(false)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, "second fails", err.Error())
			},
		},
		"second fails with pipeline continuation": {
			configureMocks: func(t *testing.T, ctx heimdall.RequestContext, first *rulemocks.SubjectHandlerMock,
				second *rulemocks.SubjectHandlerMock, sub *subject.Subject,
			) {
				t.Helper()

				first.EXPECT().Execute(ctx, sub).Return(nil)
				second.EXPECT().Execute(ctx, sub).Return(errors.New("second fails"))
				second.EXPECT().ContinueOnError().Return(true)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"tls related error stops pipeline execution": {
			configureMocks: func(t *testing.T, ctx heimdall.RequestContext, first *rulemocks.SubjectHandlerMock,
				_ *rulemocks.SubjectHandlerMock, sub *subject.Subject,
			) {
				t.Helper()

				first.EXPECT().Execute(ctx, sub).Return(errors.New("tls: some error"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			sub := &subject.Subject{ID: "foo"}

			ctx := mocks.NewRequestContextMock(t)
			ctx.EXPECT().Context().Return(t.Context())

			handler1 := rulemocks.NewSubjectHandlerMock(t)
			handler2 := rulemocks.NewSubjectHandlerMock(t)
			tc.configureMocks(t, ctx, handler1, handler2, sub)

			handler := compositeSubjectHandler{handler1, handler2}

			// WHEN
			err := handler.Execute(ctx, sub)

			// THEN
			tc.assert(t, err)
		})
	}
}
