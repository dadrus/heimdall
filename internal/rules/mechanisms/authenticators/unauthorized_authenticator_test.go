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

	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
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
	step, err := mechanisms.CreateStep(types.StepDefinition{ID: ""})
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
		stepID  string
		newConf map[string]any
		assert  func(t *testing.T, err error, prototype *unauthorizedAuthenticator, configured *unauthorizedAuthenticator)
	}{
		"without new config and step ID": {
			assert: func(t *testing.T, err error, prototype *unauthorizedAuthenticator, configured *unauthorizedAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"with new config": {
			newConf: map[string]any{"foo": "bar"},
			assert: func(t *testing.T, err error, _ *unauthorizedAuthenticator, _ *unauthorizedAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "cannot be reconfigured")
			},
		},
		"with new step ID": {
			stepID: "foo",
			assert: func(t *testing.T, err error, prototype *unauthorizedAuthenticator, configured *unauthorizedAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, "with new step ID", prototype.ID())
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
			step, err := mechanism.CreateStep(types.StepDefinition{ID: tc.stepID, Config: tc.newConf})

			// THEN
			auth, ok := step.(*unauthorizedAuthenticator)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, configured, auth)
		})
	}
}

func TestUnauthorizedAuthenticatorIsInsecure(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := unauthorizedAuthenticator{}

	// WHEN & THEN
	require.False(t, auth.IsInsecure())
}
