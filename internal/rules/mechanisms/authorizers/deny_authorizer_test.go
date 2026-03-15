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

package authorizers

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
)

func TestDenyAuthorizerCreateStep(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		stepDef types.StepDefinition
		assert  func(t *testing.T, err error, prototype, configured *denyAuthorizer)
	}{
		"no new config and no step ID": {
			assert: func(t *testing.T, err error, prototype, configured *denyAuthorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"no new config but with step ID": {
			stepDef: types.StepDefinition{ID: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *denyAuthorizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, configured, prototype)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "foo", configured.ID())
				assert.Equal(t, types.KindAuthorizer, configured.Kind())
			},
		},
		"with new config": {
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"foo": "bar"}},
			assert: func(t *testing.T, err error, _, _ *denyAuthorizer) {
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

			mech, err := newDenyAuthorizer(appCtx, uc, nil)
			require.NoError(t, err)

			configured, ok := mech.(*denyAuthorizer)
			require.True(t, ok)

			// WHEN
			conf, err := mech.CreateStep(tc.stepDef)

			// THEN
			auth, ok := conf.(*denyAuthorizer)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, configured, auth)
		})
	}
}

func TestDenyAuthorizerExecute(t *testing.T) {
	t.Parallel()

	// GIVEN
	var identifier interface{ ID() string }

	ctx := mocks.NewContextMock(t)
	ctx.EXPECT().Context().Return(t.Context())

	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Logger().Return(log.Logger)

	mech, err := newDenyAuthorizer(appCtx, "bar", nil)
	require.NoError(t, err)
	step, err := mech.CreateStep(types.StepDefinition{ID: ""})
	require.NoError(t, err)

	// WHEN
	err = step.Execute(ctx, nil)

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, pipeline.ErrAuthorization)
	require.Contains(t, err.Error(), "denied by authorizer")

	require.ErrorAs(t, err, &identifier)
	assert.Equal(t, "bar", identifier.ID())
}

func TestDenyAuthorizerAccept(t *testing.T) {
	t.Parallel()

	mech := &denyAuthorizer{}

	mech.Accept(nil)
}
