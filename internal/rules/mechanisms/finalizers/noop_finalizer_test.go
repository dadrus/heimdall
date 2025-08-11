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

package finalizers

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestNoopFinalizerExecution(t *testing.T) {
	t.Parallel()

	// GIVEN
	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Logger().Return(log.Logger)

	ctx := mocks.NewRequestContextMock(t)
	ctx.EXPECT().Context().Return(t.Context())

	finalizer := newNoopFinalizer(appCtx, "foo")

	// WHEN
	err := finalizer.Execute(ctx, nil)

	// THEN
	require.NoError(t, err)
	assert.Equal(t, "foo", finalizer.ID())
	assert.False(t, finalizer.ContinueOnError())
}

func TestCreateNoopFinalizerFromPrototype(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		stepID  string
		newConf map[string]any
		assert  func(t *testing.T, err error, prototype *noopFinalizer, configured *noopFinalizer)
	}{
		"no new config and no step ID": {
			assert: func(t *testing.T, err error, prototype *noopFinalizer, configured *noopFinalizer) {
				t.Helper()

				assert.Equal(t, prototype, configured)
			},
		},
		"no new config but with step ID": {
			stepID: "foo",
			assert: func(t *testing.T, err error, prototype *noopFinalizer, configured *noopFinalizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, configured, prototype)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "foo", configured.ID())
			},
		},
		"with new config": {
			newConf: map[string]any{"foo": "bar"},
			assert: func(t *testing.T, err error, _ *noopFinalizer, _ *noopFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "cannot be reconfigured")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Logger().Return(log.Logger)

			prototype := newNoopFinalizer(appCtx, uc)

			// WHEN
			conf, err := prototype.WithConfig(tc.stepID, tc.newConf)
			authz, ok := conf.(*noopFinalizer)

			// THEN
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, authz)
		})
	}
}
