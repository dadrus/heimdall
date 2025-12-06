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

package authenticators

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
)

func TestUnauthorizedAuthenticatorExecute(t *testing.T) {
	t.Parallel()
	// GIVEN
	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Logger().Return(log.Logger)

	var identifier interface {
		ID() string
		Name() string
	}

	ctx := mocks.NewContextMock(t)
	ctx.EXPECT().Context().Return(t.Context())

	mechanisms, err := newUnauthorizedAuthenticator(appCtx, "unauth", nil)
	require.NoError(t, err)
	step, err := mechanisms.CreateStep(types.StepDefinition{})
	require.NoError(t, err)

	// WHEN
	err = step.Execute(ctx, nil)

	// THEN
	require.ErrorIs(t, err, heimdall.ErrAuthentication)
	require.ErrorContains(t, err, "denied by authenticator")

	require.ErrorAs(t, err, &identifier)
	assert.Equal(t, "unauth", identifier.ID())
	assert.Equal(t, identifier.Name(), identifier.ID())
}

func TestUnauthorizedAuthenticatorCreateStep(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		stepDef types.StepDefinition
		assert  func(t *testing.T, err error, prototype, configured *unauthorizedAuthenticator)
	}{
		"no step definition": {
			assert: func(t *testing.T, err error, prototype, configured *unauthorizedAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"step definition with config": {
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"foo": "bar"}},
			assert: func(t *testing.T, err error, _, _ *unauthorizedAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "cannot be reconfigured")
			},
		},
		"step definition with ID": {
			stepDef: types.StepDefinition{ID: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *unauthorizedAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, "step definition with ID", prototype.ID())
				assert.False(t, configured.IsInsecure())
				assert.Equal(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
			},
		},
		"step definition with principal": {
			stepDef: types.StepDefinition{Principal: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *unauthorizedAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.Name(), configured.ID())
				assert.Equal(t, "step definition with principal", prototype.ID())
				assert.False(t, configured.IsInsecure())
				assert.NotEqual(t, prototype.PrincipalName(), configured.PrincipalName())
				assert.Equal(t, "foo", configured.PrincipalName())
				assert.Equal(t, types.KindAuthenticator, configured.Kind())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Logger().Return(log.Logger)

			mechanism, err := newUnauthorizedAuthenticator(appCtx, uc, nil)
			require.NoError(t, err)

			configured, ok := mechanism.(*unauthorizedAuthenticator)
			require.True(t, ok)

			// WHEN
			step, err := mechanism.CreateStep(tc.stepDef)

			// THEN
			auth, ok := step.(*unauthorizedAuthenticator)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, configured, auth)
		})
	}
}

func TestUnauthorizedAuthenticatorAccept(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := &unauthorizedAuthenticator{}
	visitor := mocks.NewVisitorMock(t)

	visitor.EXPECT().VisitInsecure(auth)
	visitor.EXPECT().VisitPrincipalNamer(auth)

	// WHEN
	auth.Accept(visitor)

	// THEN expected calls are done
}
