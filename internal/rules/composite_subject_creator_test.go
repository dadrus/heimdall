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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	rulemocks "github.com/dadrus/heimdall/internal/rules/mocks"
)

func TestCompositeSubjectCreatorExecution(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		subjectCreator func(t *testing.T, ctx heimdall.RequestContext, sub *subject.Subject) compositeSubjectCreator
		assert         func(t *testing.T, err error)
	}{
		"with fallback to second authenticator": {
			subjectCreator: func(t *testing.T, ctx heimdall.RequestContext, sub *subject.Subject) compositeSubjectCreator {
				t.Helper()

				auth1 := rulemocks.NewSubjectCreatorMock(t)
				auth2 := rulemocks.NewSubjectCreatorMock(t)

				auth1.EXPECT().Execute(ctx).Return(nil, errors.New("test error"))
				auth2.EXPECT().Execute(ctx).Return(sub, nil)

				return compositeSubjectCreator{auth1, auth2}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"no fallback due to tls error": {
			subjectCreator: func(t *testing.T, ctx heimdall.RequestContext, sub *subject.Subject) compositeSubjectCreator {
				t.Helper()

				auth1 := rulemocks.NewSubjectCreatorMock(t)
				auth2 := rulemocks.NewSubjectCreatorMock(t)

				auth1.EXPECT().Execute(ctx).Return(nil, errors.New("test error: tls: some error"))

				return compositeSubjectCreator{auth1, auth2}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
			},
		},
		"with fallback but both authenticators returning errors": {
			subjectCreator: func(t *testing.T, ctx heimdall.RequestContext, _ *subject.Subject) compositeSubjectCreator {
				t.Helper()

				auth1 := rulemocks.NewSubjectCreatorMock(t)
				auth2 := rulemocks.NewSubjectCreatorMock(t)

				auth1.EXPECT().Execute(ctx).Return(nil, errors.New("test error 1"))
				auth2.EXPECT().Execute(ctx).Return(nil, errors.New("test error 2"))

				return compositeSubjectCreator{auth1, auth2}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error 2")
			},
		},
		"only the first authenticator is executed": {
			subjectCreator: func(t *testing.T, ctx heimdall.RequestContext, sub *subject.Subject) compositeSubjectCreator {
				t.Helper()

				auth1 := rulemocks.NewSubjectCreatorMock(t)
				auth2 := rulemocks.NewSubjectCreatorMock(t)

				auth1.EXPECT().Execute(ctx).Return(sub, nil)

				return compositeSubjectCreator{auth1, auth2}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			sub := &subject.Subject{ID: "foo"}

			ctx := mocks.NewRequestContextMock(t)
			ctx.EXPECT().Context().Return(t.Context())

			auth := tc.subjectCreator(t, ctx, sub)

			// WHEN
			rSub, err := auth.Execute(ctx)

			// THEN
			tc.assert(t, err)

			if err == nil {
				assert.Equal(t, sub, rSub)
			}
		})
	}
}
