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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	rulemocks "github.com/dadrus/heimdall/internal/rules/mocks"
	"github.com/dadrus/heimdall/internal/subject"
)

func TestCompositeSubjectHandlerExecution(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		configureMocks func(t *testing.T, ctx heimdall.Context, first *rulemocks.SubjectHandlerMock,
			second *rulemocks.SubjectHandlerMock, sub subject.Subject)
		assert func(t *testing.T, err error)
	}{
		{
			uc: "All succeeded",
			configureMocks: func(t *testing.T, ctx heimdall.Context, first *rulemocks.SubjectHandlerMock,
				second *rulemocks.SubjectHandlerMock, sub subject.Subject,
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
		{
			uc: "First fails without pipeline continuation",
			configureMocks: func(t *testing.T, ctx heimdall.Context, first *rulemocks.SubjectHandlerMock,
				_ *rulemocks.SubjectHandlerMock, sub subject.Subject,
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
		{
			uc: "First fails with pipeline continuation, second succeeds",
			configureMocks: func(t *testing.T, ctx heimdall.Context, first *rulemocks.SubjectHandlerMock,
				second *rulemocks.SubjectHandlerMock, sub subject.Subject,
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
		{
			uc: "Second fails without pipeline continuation",
			configureMocks: func(t *testing.T, ctx heimdall.Context, first *rulemocks.SubjectHandlerMock,
				second *rulemocks.SubjectHandlerMock, sub subject.Subject,
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
		{
			uc: "Second fails with pipeline continuation",
			configureMocks: func(t *testing.T, ctx heimdall.Context, first *rulemocks.SubjectHandlerMock,
				second *rulemocks.SubjectHandlerMock, sub subject.Subject,
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
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			sub := subject.Subject{"Subject": &subject.Principal{ID: "foo"}}

			ctx := mocks.NewContextMock(t)
			ctx.EXPECT().AppContext().Return(context.Background())

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
