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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/secrets/types/mocks"
)

func TestAPIKeyInit(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, sm *mocks.ManagerMock)
		assert func(t *testing.T, err error, ak *APIKey)
	}{
		"fails to resolve secret": {
			setup: func(t *testing.T, sm *mocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, ak *APIKey) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving api key secret")

				assert.Nil(t, ak.Hash())
				_, ok := ak.resolver.Get()
				assert.False(t, ok)
			},
		},
		"fails due to an invalid secret kind": {
			setup: func(t *testing.T, sm *mocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).
					Return(types.NewSymmetricKeySecret("bar", "baz", []byte{}), nil)
			},
			assert: func(t *testing.T, err error, ak *APIKey) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorIs(t, err, secrets.ErrSecretKindMismatch)
				require.ErrorContains(t, err, "failed resolving api key secret")

				assert.Nil(t, ak.Hash())
				_, ok := ak.resolver.Get()
				require.False(t, ok)
			},
		},
		"succeeds": {
			setup: func(t *testing.T, sm *mocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).
					Return(types.NewStringSecret("bar", "baz"), nil)
				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).Return(func() {}, nil)
			},
			assert: func(t *testing.T, err error, ak *APIKey) {
				t.Helper()

				require.NoError(t, err)

				require.Equal(t, "header", ak.In)
				require.Equal(t, "foo", ak.Name)
				require.NotNil(t, ak.resolver)

				val, ok := ak.resolver.Get()
				require.True(t, ok)
				assert.Equal(t, "baz", val)
				assert.NotEmpty(t, ak.Hash())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			secret := config.Secret{Source: "foo", Selector: "bar"}
			sm := mocks.NewManagerMock(t)
			// sm.EXPECT().Subscribe(secret, mock.Anything).Return(func() {}, nil)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().SecretsManager().Return(sm)

			ak := &APIKey{
				In:     "header",
				Name:   "foo",
				Secret: secret,
			}

			tc.setup(t, sm)

			// WHEN
			err := ak.init(t.Context(), appCtx)

			// THEN
			tc.assert(t, err, ak)
		})
	}
}

func TestApiKeyApply(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ignoreInitError bool
		config          *APIKey
		setup           func(t *testing.T, sm *mocks.ManagerMock)
		assert          func(t *testing.T, err error, req *http.Request)
	}{
		"no secret available": {
			ignoreInitError: true,
			config:          &APIKey{In: "header", Name: "Foo"},
			setup: func(t *testing.T, sm *mocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, _ *http.Request) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "api key secret is not available")
			},
		},
		"header strategy": {
			config: &APIKey{In: "header", Name: "Foo"},
			setup: func(t *testing.T, sm *mocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).Return(func() {}, nil)
				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).
					Return(types.NewStringSecret("bar", "baz"), nil)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "baz", req.Header.Get("Foo"))
			},
		},
		"cookie strategy": {
			config: &APIKey{In: "cookie", Name: "Foo"},
			setup: func(t *testing.T, sm *mocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).Return(func() {}, nil)
				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).
					Return(types.NewStringSecret("bar", "baz"), nil)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)

				cookie, err := req.Cookie("Foo")
				require.NoError(t, err)
				assert.Equal(t, "baz", cookie.Value)
			},
		},
		"query strategy": {
			config: &APIKey{In: "query", Name: "Foo"},
			setup: func(t *testing.T, sm *mocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).Return(func() {}, nil)
				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).
					Return(types.NewStringSecret("bar", "baz"), nil)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)

				query := req.URL.Query()
				assert.Len(t, query, 2)
				assert.Equal(t, "baz", query.Get("Foo"))
				assert.Equal(t, "foo", query.Get("bar"))
			},
		},
		"invalid strategy": {
			config: &APIKey{In: "foo", Name: "Foo"},
			setup: func(t *testing.T, sm *mocks.ManagerMock) {
				t.Helper()

				sm.EXPECT().Subscribe(mock.Anything, mock.Anything).Return(func() {}, nil)
				sm.EXPECT().ResolveSecret(mock.Anything, mock.Anything).
					Return(types.NewStringSecret("bar", "baz"), nil)
			},
			assert: func(t *testing.T, err error, _ *http.Request) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "unsupported")
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

			sm := mocks.NewManagerMock(t)
			tc.setup(t, sm)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().SecretsManager().Return(sm)

			err = tc.config.init(t.Context(), appCtx)
			if !tc.ignoreInitError {
				require.NoError(t, err)
			}

			// WHEN
			err = tc.config.Apply(req)

			// THEN
			tc.assert(t, err, req)
		})
	}
}
