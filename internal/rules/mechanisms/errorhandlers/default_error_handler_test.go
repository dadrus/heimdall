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

package errorhandlers

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type testResponseDecorator struct {
	code    int
	headers map[string][]string
	body    string
}

func (d testResponseDecorator) DecorateErrorResponse(_ error, er *pipeline.ErrorResponse) {
	er.Code = d.code
	er.Headers = d.headers
	er.Body = d.body
}

func TestDefaultErrorHandlerExecute(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		cause            error
		configureContext func(t *testing.T, ctx *mocks.ContextMock, cause error)
	}{
		"without decorator keeps original error": {
			cause: pipeline.ErrAuthentication,
			configureContext: func(t *testing.T, ctx *mocks.ContextMock, cause error) {
				t.Helper()

				ctx.EXPECT().Error().Return(cause)
				ctx.EXPECT().SetError(mock.MatchedBy(func(response *pipeline.ResponseError) bool {
					t.Helper()

					assert.Equal(t, 0, response.Code)
					assert.Nil(t, response.Headers)
					assert.Empty(t, response.Body)
					assert.ErrorIs(t, response.Cause, pipeline.ErrAuthentication)

					return true
				}))
			},
		},
		"response decorator from error context is applied": {
			cause: errorchain.New(pipeline.ErrAuthentication).WithErrorContext(testResponseDecorator{
				code:    418,
				headers: map[string][]string{"WWW-Authenticate": {"Basic realm=\"foo\""}},
				body:    "custom body",
			}),
			configureContext: func(t *testing.T, ctx *mocks.ContextMock, cause error) {
				t.Helper()

				ctx.EXPECT().Error().Return(cause)
				ctx.EXPECT().SetError(mock.MatchedBy(func(response *pipeline.ResponseError) bool {
					t.Helper()

					assert.Equal(t, 418, response.Code)
					assert.Equal(t, map[string][]string{"WWW-Authenticate": {"Basic realm=\"foo\""}}, response.Headers)
					assert.Equal(t, "custom body", response.Body)
					assert.ErrorIs(t, response.Cause, pipeline.ErrAuthentication)

					return true
				}))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Logger().Return(log.Logger)

			ctx := mocks.NewContextMock(t)
			ctx.EXPECT().Context().Return(t.Context())
			tc.configureContext(t, ctx, tc.cause)

			mech, err := newDefaultErrorHandler(appCtx, "foo", nil)
			require.NoError(t, err)

			step, err := mech.CreateStep(types.StepDefinition{ID: ""})
			require.NoError(t, err)

			// WHEN & THEN
			require.NoError(t, step.Execute(ctx, nil))
		})
	}
}

func TestDefaultErrorHandlerCreateStep(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		stepDef types.StepDefinition
		assert  func(t *testing.T, err error, prototype, configured *defaultErrorHandler)
	}{
		"no new config and no step ID": {
			assert: func(t *testing.T, err error, prototype, configured *defaultErrorHandler) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
		"no new config but with step ID": {
			stepDef: types.StepDefinition{ID: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *defaultErrorHandler) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, configured, prototype)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, types.KindErrorHandler, configured.Kind())
				assert.Equal(t, prototype.Type(), configured.Type())
			},
		},
		"with new config": {
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"foo": "bar"}},
			assert: func(t *testing.T, err error, _, _ *defaultErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "cannot be reconfigured")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Logger().Return(log.Logger)

			mech, err := newDefaultErrorHandler(appCtx, uc, nil)
			require.NoError(t, err)

			configured, ok := mech.(*defaultErrorHandler)
			require.True(t, ok)

			// WHEN
			step, err := mech.CreateStep(tc.stepDef)

			// THEN
			eh, ok := step.(*defaultErrorHandler)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, configured, eh)
		})
	}
}

func TestDefaultErrorHandlerAccept(t *testing.T) {
	t.Parallel()

	mech := &defaultErrorHandler{}

	mech.Accept(nil)
}
