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

package authstrategy

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
)

func TestBasicAuthInit(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, sm *mocks.ManagerMock)
		assert func(t *testing.T, err error, ba *BasicAuth)
	}{
		"fails to resolve credentials": {
			setup: func(t *testing.T, sm *mocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveCredentials(mock.Anything, mock.Anything).
					Return(nil, errors.New("boom"))
			},
			assert: func(t *testing.T, err error, ba *BasicAuth) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving basic auth credentials")

				assert.Nil(t, ba.Hash())
				_, ok := ba.resolver.Get()
				require.False(t, ok)
			},
		},
		"fails due to an invalid credentials structure": {
			setup: func(t *testing.T, sm *mocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveCredentials(mock.Anything, mock.Anything).
					Return(types.NewCredentials("foo", "bar", map[string]any{
						"foo": "baz",
						"bar": "foo",
					}), nil)
			},
			assert: func(t *testing.T, err error, ba *BasicAuth) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "invalid credentials payload")

				assert.Nil(t, ba.Hash())
				_, ok := ba.resolver.Get()
				require.False(t, ok)
			},
		},
		"succeeds": {
			setup: func(t *testing.T, sm *mocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).Return(func() {}, nil)
				sm.EXPECT().ResolveCredentials(mock.Anything, mock.Anything).
					Return(types.NewCredentials("foo", "bar", map[string]any{
						"user_id":  "baz",
						"password": "foo",
					}), nil)
			},
			assert: func(t *testing.T, err error, ba *BasicAuth) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, ba.resolver)

				val, ok := ba.resolver.Get()
				require.True(t, ok)
				assert.Equal(t, "baz", val.UserID)
				assert.Equal(t, "foo", val.Password)
				assert.NotEmpty(t, ba.Hash())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			secret := config.Secret{Source: "foo", Selector: "bar"}
			sm := mocks.NewManagerMock(t)

			tc.setup(t, sm)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().SecretsManager().Return(sm)

			ak := &BasicAuth{Credentials: secret}

			// WHEN
			err := ak.init(t.Context(), appCtx)

			// THEN
			tc.assert(t, err, ak)
		})
	}
}

func TestBasicAuthApply(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ignoreInitError bool
		setup           func(t *testing.T, sm *mocks.ManagerMock)
		assert          func(t *testing.T, err error, req *http.Request)
	}{
		"no secret available": {
			ignoreInitError: true,
			setup: func(t *testing.T, sm *mocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveCredentials(mock.Anything, mock.Anything).
					Return(nil, errors.New("boom"))
			},
			assert: func(t *testing.T, err error, _ *http.Request) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "basic auth credentials are not available")
			},
		},
		"Authorization header is set": {
			setup: func(t *testing.T, sm *mocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).Return(func() {}, nil)
				sm.EXPECT().ResolveCredentials(mock.Anything, mock.Anything).
					Return(types.NewCredentials("foo", "bar", map[string]any{
						"user_id":  "baz",
						"password": "foo",
					}), nil)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)

				username, password, ok := req.BasicAuth()
				assert.True(t, ok)
				assert.Equal(t, "baz", username)
				assert.Equal(t, "foo", password)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"http//example.com/test?bar=foo",
				nil,
			)
			require.NoError(t, err)

			ba := &BasicAuth{}

			sm := mocks.NewManagerMock(t)
			tc.setup(t, sm)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().SecretsManager().Return(sm)

			err = ba.init(t.Context(), appCtx)
			if !tc.ignoreInitError {
				require.NoError(t, err)
			}

			// WHEN
			err = ba.Apply(req)

			// THEN
			tc.assert(t, err, req)
		})
	}
}
