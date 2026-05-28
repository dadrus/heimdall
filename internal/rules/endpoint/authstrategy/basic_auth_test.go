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
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/validation"
)

func TestBasicAuthCredentialsHash(t *testing.T) {
	t.Parallel()

	creds := basicAuthCredentials{
		UserID:   "baz",
		Password: "foo",
	}

	require.NotEmpty(t, creds.Hash())
}

func TestBasicAuthInit(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock)
		assert func(t *testing.T, err error, ba *BasicAuth)
	}{
		"fails to resolve credentials": {
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, _ *secretsmocks.CredentialsHandleMock) {
				t.Helper()

				sr.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, ba *BasicAuth) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving basic auth credentials")

				assert.Nil(t, ba.Hash())
				assert.Nil(t, ba.informer)
			},
		},
		"succeeds": {
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock) {
				t.Helper()

				creds := types.NewCredentials("bar", map[string]any{
					"user_id":  "baz",
					"password": "foo",
				})

				sr.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						err := cb(t.Context(), creds)
						require.NoError(t, err)

						return true
					}))
			},
			assert: func(t *testing.T, err error, ba *BasicAuth) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ba.informer)

				val, ok := ba.informer.Get()
				require.True(t, ok)
				assert.Equal(t, "baz", val.UserID)
				assert.Equal(t, "foo", val.Password)
				assert.NotEmpty(t, ba.Hash())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			secret := config.Secret{Source: "foo", Selector: "bar"}

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewCredentialsHandleMock(t)

			tc.setup(t, sr, handle)

			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().SecretResolver().Return(sr)
			appCtx.EXPECT().DecoderFactory().Maybe().
				Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))

			ba := &BasicAuth{Credentials: secret}

			err = ba.init(appCtx)

			tc.assert(t, err, ba)
		})
	}
}

func TestBasicAuthApply(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		credentials config.Secret
		setup       func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock)
		assert      func(t *testing.T, err error, req *http.Request)
	}{
		"no credentials available": {
			credentials: config.Secret{Source: "foo", Selector: "bar"},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock) {
				t.Helper()

				sr.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(handle, nil)

				handle.EXPECT().OnUpdate(mock.Anything)
			},
			assert: func(t *testing.T, err error, _ *http.Request) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "basic auth credentials are not available")
			},
		},
		"invalid credentials structure": {
			credentials: config.Secret{Source: "foo", Selector: "bar"},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock) {
				t.Helper()

				creds := types.NewCredentials("bar", map[string]any{
					"foo": "baz",
					"bar": "foo",
				})

				sr.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						err := cb(t.Context(), creds)
						require.Error(t, err)
						require.ErrorIs(t, err, pipeline.ErrConfiguration)
						require.ErrorContains(t, err, "failed decoding basic auth credentials")

						return true
					}))
			},
			assert: func(t *testing.T, err error, _ *http.Request) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "basic auth credentials are not available")
			},
		},
		"authorization header is set": {
			credentials: config.Secret{Source: "foo", Selector: "bar"},
			setup: func(t *testing.T, sr *secretsmocks.ResolverMock, handle *secretsmocks.CredentialsHandleMock) {
				t.Helper()

				creds := types.NewCredentials("bar", map[string]any{
					"user_id":  "baz",
					"password": "foo",
				})

				sr.EXPECT().
					Credentials(secrets.Reference{Source: "foo", Selector: "bar"}).
					Return(handle, nil)

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Credentials]) bool {
						err := cb(t.Context(), creds)
						require.NoError(t, err)

						return true
					}))
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
			t.Parallel()

			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			req, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"http://example.com/test?bar=foo",
				nil,
			)
			require.NoError(t, err)

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewCredentialsHandleMock(t)

			tc.setup(t, sr, handle)

			ba := &BasicAuth{Credentials: tc.credentials}

			if tc.credentials.Source != "" || tc.credentials.Selector != "" {
				appCtx := app.NewContextMock(t)
				appCtx.EXPECT().SecretResolver().Return(sr)
				appCtx.EXPECT().DecoderFactory().Maybe().
					Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))

				err = ba.init(appCtx)
				require.NoError(t, err)
			}

			err = ba.Apply(req)

			tc.assert(t, err, req)
		})
	}
}

func TestToBasicAuthCredentials(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		credentials secrets.Credentials
		assert      func(t *testing.T, got basicAuthCredentials, err error)
	}{
		"decodes credentials": {
			credentials: types.NewCredentials("bar", map[string]any{
				"user_id":  "baz",
				"password": "foo",
			}),
			assert: func(t *testing.T, got basicAuthCredentials, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "baz", got.UserID)
				assert.Equal(t, "foo", got.Password)
			},
		},
		"returns decode error": {
			credentials: types.NewCredentials("bar", map[string]any{
				"foo": "baz",
				"bar": "foo",
			}),
			assert: func(t *testing.T, got basicAuthCredentials, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Empty(t, got.UserID)
				assert.Empty(t, got.Password)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))

			got, err := toBasicAuthCredentials(df)(tc.credentials)

			tc.assert(t, got, err)
		})
	}
}
