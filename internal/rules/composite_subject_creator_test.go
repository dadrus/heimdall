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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	rulemocks "github.com/dadrus/heimdall/internal/rules/mocks"
	"github.com/dadrus/heimdall/internal/subject"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCompositeSubjectCreatorExecution(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		configureMocks func(t *testing.T, ctx heimdall.Context, first *rulemocks.SubjectHandlerMock,
			second *rulemocks.SubjectHandlerMock, sub subject.Subject)
		assert func(t *testing.T, err error)
	}{
		{
			uc: "with fallback due to argument error on first authenticator",
			configureMocks: func(t *testing.T, ctx heimdall.Context, first *rulemocks.SubjectHandlerMock,
				second *rulemocks.SubjectHandlerMock, sub subject.Subject,
			) {
				t.Helper()

				first.EXPECT().Execute(ctx, sub).Return(heimdall.ErrArgument)
				second.EXPECT().Execute(ctx, sub).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "with fallback and both authenticators returning argument error",
			configureMocks: func(t *testing.T, ctx heimdall.Context, first *rulemocks.SubjectHandlerMock,
				second *rulemocks.SubjectHandlerMock, sub subject.Subject,
			) {
				t.Helper()

				first.EXPECT().Execute(ctx, sub).Return(heimdall.ErrArgument)
				second.EXPECT().Execute(ctx, sub).Return(heimdall.ErrArgument)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, err, heimdall.ErrArgument)
			},
		},
		{
			uc: "without fallback as first authenticator returns an error not equal to argument error",
			configureMocks: func(t *testing.T, ctx heimdall.Context, first *rulemocks.SubjectHandlerMock,
				_ *rulemocks.SubjectHandlerMock, sub subject.Subject,
			) {
				t.Helper()

				first.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				first.EXPECT().ContinueOnError().Return(false)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, err, testsupport.ErrTestPurpose)
			},
		},
		{
			uc: "with fallback on error since first authenticator allows fallback on any error",
			configureMocks: func(t *testing.T, ctx heimdall.Context, first *rulemocks.SubjectHandlerMock,
				second *rulemocks.SubjectHandlerMock, sub subject.Subject,
			) {
				t.Helper()

				first.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				first.EXPECT().ContinueOnError().Return(true)
				second.EXPECT().Execute(ctx, sub).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			sub := subject.Subject{"Subject": &subject.Principal{ID: "foo"}}

			ctx := mocks.NewContextMock(t)
			ctx.EXPECT().AppContext().Return(context.Background())

			auth1 := rulemocks.NewSubjectHandlerMock(t)
			auth2 := rulemocks.NewSubjectHandlerMock(t)
			tc.configureMocks(t, ctx, auth1, auth2, sub)

			auth := compositeSubjectCreator{auth1, auth2}

			// WHEN
			err := auth.Execute(ctx, sub)

			// THEN
			tc.assert(t, err)
		})
	}
}
