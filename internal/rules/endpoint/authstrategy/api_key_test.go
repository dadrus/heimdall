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
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
)

func TestAPIKeyInit(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock)
		assert func(t *testing.T, err error, ak *APIKey)
	}{
		"fails to resolve secret": {
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, _ *secretsmocks.SecretHandleMock) {
				t.Helper()

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, ak *APIKey) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving api key secret")

				assert.Nil(t, ak.Hash())
				assert.Nil(t, ak.informer)
			},
		},
		"succeeds": {
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock) {
				t.Helper()

				secret := types.NewStringSecret("bar", "baz")

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(context.Background(), secret)
						require.NoError(t, err)

						return true
					}))

				handle.EXPECT().
					Get(mock.Anything).
					Return(secret, true)
			},
			assert: func(t *testing.T, err error, ak *APIKey) {
				t.Helper()

				require.NoError(t, err)

				require.Equal(t, "header", ak.In)
				require.Equal(t, "foo", ak.Name)
				require.NotNil(t, ak.informer)

				val, ok := ak.informer.Get(t.Context())
				require.True(t, ok)
				assert.Equal(t, "baz", val)
				assert.NotEmpty(t, ak.Hash())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			secret := config.Secret{Source: "foo", Selector: "bar"}

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewSecretHandleMock(t)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().SecretResolver().Return(sr)

			ak := &APIKey{
				In:     "header",
				Name:   "foo",
				Secret: secret,
			}

			tc.setup(t, sr, handle)

			err := ak.init(t.Context(), appCtx)

			tc.assert(t, err, ak)
		})
	}
}

func TestAPIKeyApply(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config *APIKey
		setup  func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock)
		assert func(t *testing.T, err error, req *http.Request)
	}{
		"no secret available": {
			config: &APIKey{
				In:     "header",
				Name:   "Foo",
				Secret: config.Secret{Source: "foo", Selector: "bar"},
			},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock) {
				t.Helper()

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.Anything)

				handle.EXPECT().
					Get(mock.Anything).
					Return(nil, false)
			},
			assert: func(t *testing.T, err error, _ *http.Request) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "api key secret is not available")
			},
		},
		"header strategy": {
			config: &APIKey{
				In:     "header",
				Name:   "Foo",
				Secret: config.Secret{Source: "foo", Selector: "bar"},
			},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock) {
				t.Helper()

				secret := types.NewStringSecret("bar", "baz")

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(context.Background(), secret)
						require.NoError(t, err)

						return true
					}))

				handle.EXPECT().
					Get(mock.Anything).
					Return(secret, true)
			},
			assert: func(t *testing.T, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "baz", req.Header.Get("Foo"))
			},
		},
		"cookie strategy": {
			config: &APIKey{
				In:     "cookie",
				Name:   "Foo",
				Secret: config.Secret{Source: "foo", Selector: "bar"},
			},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock) {
				t.Helper()

				secret := types.NewStringSecret("bar", "baz")

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(context.Background(), secret)
						require.NoError(t, err)

						return true
					}))

				handle.EXPECT().
					Get(mock.Anything).
					Return(secret, true)
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
			config: &APIKey{
				In:     "query",
				Name:   "Foo",
				Secret: config.Secret{Source: "foo", Selector: "bar"},
			},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock) {
				t.Helper()

				secret := types.NewStringSecret("bar", "baz")

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(context.Background(), secret)
						require.NoError(t, err)

						return true
					}))

				handle.EXPECT().
					Get(mock.Anything).
					Return(secret, true)
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
			config: &APIKey{
				In:     "foo",
				Name:   "Foo",
				Secret: config.Secret{Source: "foo", Selector: "bar"},
			},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock) {
				t.Helper()

				secret := types.NewStringSecret("bar", "baz")

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(context.Background(), secret)
						require.NoError(t, err)

						return true
					}))

				handle.EXPECT().
					Get(mock.Anything).
					Return(secret, true)
			},
			assert: func(t *testing.T, err error, _ *http.Request) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "unsupported")
			},
		},
		"invalid secret kind": {
			config: &APIKey{
				In:     "header",
				Name:   "Foo",
				Secret: config.Secret{Source: "foo", Selector: "bar"},
			},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.SecretHandleMock) {
				t.Helper()

				secret := types.NewSymmetricKeySecret("bar", "baz", []byte{})

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "foo", Selector: "bar"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.Anything)

				handle.EXPECT().
					Get(mock.Anything).
					Return(secret, true)
			},
			assert: func(t *testing.T, err error, _ *http.Request) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "api key secret is not available")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			req, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"http://example.com/test?bar=foo",
				nil,
			)
			require.NoError(t, err)

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewSecretHandleMock(t)

			tc.setup(t, sr, handle)

			appCtx := app.NewContextMock(t)

			if tc.config.Secret.Source != "" || tc.config.Secret.Selector != "" {
				appCtx.EXPECT().SecretResolver().Return(sr)

				err = tc.config.init(t.Context(), appCtx)
				require.NoError(t, err)
			}

			err = tc.config.Apply(req)

			tc.assert(t, err, req)
		})
	}
}

func TestToStringSecret(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		secret secrets.Secret
		assert func(t *testing.T, value string, err error)
	}{
		"returns string secret value": {
			secret: types.NewStringSecret("bar", "baz"),
			assert: func(t *testing.T, value string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "baz", value)
			},
		},
		"returns kind mismatch for non string secret": {
			secret: types.NewSymmetricKeySecret("bar", "baz", []byte{}),
			assert: func(t *testing.T, value string, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, secrets.ErrSecretKindMismatch)
				assert.Empty(t, value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			value, err := toStringSecret(tc.secret)

			tc.assert(t, value, err)
		})
	}
}
