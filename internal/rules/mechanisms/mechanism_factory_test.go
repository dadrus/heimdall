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

package mechanisms

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authorizers"
	mocks3 "github.com/dadrus/heimdall/internal/rules/mechanisms/authorizers/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contextualizers"
	mocks4 "github.com/dadrus/heimdall/internal/rules/mechanisms/contextualizers/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers"
	mocks5 "github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/finalizers"
	mocks6 "github.com/dadrus/heimdall/internal/rules/mechanisms/finalizers/mocks"
	"github.com/dadrus/heimdall/internal/x"
)

func TestHandlerFactoryCreateAuthenticator(t *testing.T) {
	t.Parallel()

	ID := "foo"

	for _, tc := range []struct {
		uc            string
		id            string
		conf          map[string]any
		configureMock func(t *testing.T, mAuth *mocks.AuthenticatorMock)
		assert        func(t *testing.T, err error, auth authenticators.Authenticator)
	}{
		{
			uc: "no authenticator for given id",
			id: "bar",
			assert: func(t *testing.T, err error, _ authenticators.Authenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrAuthenticatorCreation)
				assert.Contains(t, err.Error(), "no authenticator prototype")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mAuth *mocks.AuthenticatorMock) {
				t.Helper()

				mAuth.EXPECT().WithConfig(mock.Anything).Return(nil, heimdall.ErrArgument)
			},
			assert: func(t *testing.T, err error, _ authenticators.Authenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrAuthenticatorCreation)
				assert.Contains(t, err.Error(), heimdall.ErrArgument.Error())
			},
		},
		{
			uc:   "successful creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mAuth *mocks.AuthenticatorMock) {
				t.Helper()

				mAuth.EXPECT().WithConfig(mock.Anything).Return(mAuth, nil)
			},
			assert: func(t *testing.T, err error, auth authenticators.Authenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, auth)
			},
		},
		{
			uc: "successful creation with empty config",
			assert: func(t *testing.T, err error, auth authenticators.Authenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, auth)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMock := x.IfThenElse(tc.configureMock != nil,
				tc.configureMock,
				func(t *testing.T, _ *mocks.AuthenticatorMock) { t.Helper() })

			mAuth := mocks.NewAuthenticatorMock(t)
			configureMock(t, mAuth)

			factory := &mechanismsFactory{
				r: &mechanismRepository{
					authenticators: map[string]authenticators.Authenticator{
						ID: mAuth,
					},
				},
			}

			id := x.IfThenElse(len(tc.id) != 0, tc.id, ID)

			// WHEN
			auth, err := factory.CreateAuthenticator("test", id, tc.conf)

			// THEN
			tc.assert(t, err, auth)
		})
	}
}

func TestHandlerFactoryCreateAuthorizer(t *testing.T) {
	t.Parallel()

	ID := "foo"

	for _, tc := range []struct {
		uc            string
		id            string
		conf          map[string]any
		configureMock func(t *testing.T, mAuth *mocks3.AuthorizerMock)
		assert        func(t *testing.T, err error, auth authorizers.Authorizer)
	}{
		{
			uc: "no authenticator for given id",
			id: "bar",
			assert: func(t *testing.T, err error, _ authorizers.Authorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrAuthorizerCreation)
				assert.Contains(t, err.Error(), "no authorizer prototype")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mAuth *mocks3.AuthorizerMock) {
				t.Helper()

				mAuth.EXPECT().WithConfig(mock.Anything).Return(nil, heimdall.ErrArgument)
			},
			assert: func(t *testing.T, err error, _ authorizers.Authorizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrAuthorizerCreation)
				assert.Contains(t, err.Error(), heimdall.ErrArgument.Error())
			},
		},
		{
			uc:   "successful creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mAuth *mocks3.AuthorizerMock) {
				t.Helper()

				mAuth.EXPECT().WithConfig(mock.Anything).Return(mAuth, nil)
			},
			assert: func(t *testing.T, err error, auth authorizers.Authorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, auth)
			},
		},
		{
			uc: "successful creation with empty config",
			assert: func(t *testing.T, err error, auth authorizers.Authorizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, auth)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMock := x.IfThenElse(tc.configureMock != nil,
				tc.configureMock,
				func(t *testing.T, _ *mocks3.AuthorizerMock) { t.Helper() })

			mAuth := mocks3.NewAuthorizerMock(t)
			configureMock(t, mAuth)

			factory := &mechanismsFactory{
				r: &mechanismRepository{
					authorizers: map[string]authorizers.Authorizer{
						ID: mAuth,
					},
				},
			}

			id := x.IfThenElse(len(tc.id) != 0, tc.id, ID)

			// WHEN
			auth, err := factory.CreateAuthorizer("test", id, tc.conf)

			// THEN
			tc.assert(t, err, auth)
		})
	}
}

func TestHandlerFactoryCreateContextualizer(t *testing.T) {
	t.Parallel()

	ID := "foo"

	for _, tc := range []struct {
		uc            string
		id            string
		conf          map[string]any
		configureMock func(t *testing.T, mContextualizer *mocks4.ContextualizerMock)
		assert        func(t *testing.T, err error, contextualizer contextualizers.Contextualizer)
	}{
		{
			uc: "no contextualizer for given id",
			id: "bar",
			assert: func(t *testing.T, err error, _ contextualizers.Contextualizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrContextualizerCreation)
				assert.Contains(t, err.Error(), "no contextualizer prototype")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mContextualizer *mocks4.ContextualizerMock) {
				t.Helper()

				mContextualizer.EXPECT().WithConfig(mock.Anything).
					Return(nil, heimdall.ErrArgument)
			},
			assert: func(t *testing.T, err error, _ contextualizers.Contextualizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrContextualizerCreation)
				assert.Contains(t, err.Error(), heimdall.ErrArgument.Error())
			},
		},
		{
			uc:   "successful creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mContextualizer *mocks4.ContextualizerMock) {
				t.Helper()

				mContextualizer.EXPECT().WithConfig(mock.Anything).Return(mContextualizer, nil)
			},
			assert: func(t *testing.T, err error, contextualizer contextualizers.Contextualizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, contextualizer)
			},
		},
		{
			uc: "successful creation with empty config",
			assert: func(t *testing.T, err error, contextualizer contextualizers.Contextualizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, contextualizer)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMock := x.IfThenElse(tc.configureMock != nil,
				tc.configureMock,
				func(t *testing.T, _ *mocks4.ContextualizerMock) { t.Helper() })

			mContextualizer := mocks4.NewContextualizerMock(t)
			configureMock(t, mContextualizer)

			factory := &mechanismsFactory{
				r: &mechanismRepository{
					contextualizers: map[string]contextualizers.Contextualizer{
						ID: mContextualizer,
					},
				},
			}

			id := x.IfThenElse(len(tc.id) != 0, tc.id, ID)

			// WHEN
			contextualizer, err := factory.CreateContextualizer("test", id, tc.conf)

			// THEN
			tc.assert(t, err, contextualizer)
		})
	}
}

func TestHandlerFactoryCreateFinalizer(t *testing.T) {
	t.Parallel()

	ID := "foo"

	for _, tc := range []struct {
		uc            string
		id            string
		conf          map[string]any
		configureMock func(t *testing.T, mFin *mocks6.FinalizerMock)
		assert        func(t *testing.T, err error, finalizer finalizers.Finalizer)
	}{
		{
			uc: "no finalizer for given id",
			id: "bar",
			assert: func(t *testing.T, err error, _ finalizers.Finalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrFinalizerCreation)
				assert.Contains(t, err.Error(), "no finalizer prototype")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, finalizer *mocks6.FinalizerMock) {
				t.Helper()

				finalizer.EXPECT().WithConfig(mock.Anything).Return(nil, heimdall.ErrArgument)
			},
			assert: func(t *testing.T, err error, _ finalizers.Finalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrFinalizerCreation)
				assert.Contains(t, err.Error(), heimdall.ErrArgument.Error())
			},
		},
		{
			uc:   "successful creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, finalizer *mocks6.FinalizerMock) {
				t.Helper()

				finalizer.EXPECT().WithConfig(mock.Anything).Return(finalizer, nil)
			},
			assert: func(t *testing.T, err error, finalizer finalizers.Finalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, finalizer)
			},
		},
		{
			uc: "successful creation with empty config",
			assert: func(t *testing.T, err error, finalizer finalizers.Finalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, finalizer)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMock := x.IfThenElse(tc.configureMock != nil,
				tc.configureMock,
				func(t *testing.T, _ *mocks6.FinalizerMock) { t.Helper() })

			mFin := mocks6.NewFinalizerMock(t)
			configureMock(t, mFin)

			factory := &mechanismsFactory{
				r: &mechanismRepository{
					finalizers: map[string]finalizers.Finalizer{
						ID: mFin,
					},
				},
			}

			id := x.IfThenElse(len(tc.id) != 0, tc.id, ID)

			// WHEN
			finalizer, err := factory.CreateFinalizer("test", id, tc.conf)

			// THEN
			tc.assert(t, err, finalizer)
		})
	}
}

func TestHandlerFactoryCreateErrorHandler(t *testing.T) {
	t.Parallel()

	ID := "foo"

	for _, tc := range []struct {
		uc            string
		id            string
		conf          map[string]any
		configureMock func(t *testing.T, mEH *mocks5.ErrorHandlerMock)
		assert        func(t *testing.T, err error, errorHandler errorhandlers.ErrorHandler)
	}{
		{
			uc: "no error handler for given id",
			id: "bar",
			assert: func(t *testing.T, err error, _ errorhandlers.ErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrErrorHandlerCreation)
				assert.Contains(t, err.Error(), "no error handler prototype")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mEH *mocks5.ErrorHandlerMock) {
				t.Helper()

				mEH.EXPECT().WithConfig(mock.Anything).Return(nil, heimdall.ErrArgument)
			},
			assert: func(t *testing.T, err error, _ errorhandlers.ErrorHandler) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrErrorHandlerCreation)
				assert.Contains(t, err.Error(), heimdall.ErrArgument.Error())
			},
		},
		{
			uc:   "successful creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mEH *mocks5.ErrorHandlerMock) {
				t.Helper()

				mEH.EXPECT().WithConfig(mock.Anything).Return(mEH, nil)
			},
			assert: func(t *testing.T, err error, errorHandler errorhandlers.ErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, errorHandler)
			},
		},
		{
			uc: "successful creation with empty config",
			assert: func(t *testing.T, err error, errorHandler errorhandlers.ErrorHandler) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, errorHandler)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMock := x.IfThenElse(tc.configureMock != nil,
				tc.configureMock,
				func(t *testing.T, _ *mocks5.ErrorHandlerMock) { t.Helper() })

			mEH := mocks5.NewErrorHandlerMock(t)
			configureMock(t, mEH)

			factory := &mechanismsFactory{
				r: &mechanismRepository{
					errorHandlers: map[string]errorhandlers.ErrorHandler{
						ID: mEH,
					},
				},
			}

			id := x.IfThenElse(len(tc.id) != 0, tc.id, ID)

			// WHEN
			errorHandler, err := factory.CreateErrorHandler("test", id, tc.conf)

			// THEN
			tc.assert(t, err, errorHandler)
		})
	}
}

func TestCreateHandlerFactory(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		conf   *config.Configuration
		assert func(t *testing.T, err error, factory *mechanismsFactory)
	}{
		{
			uc:   "successful",
			conf: &config.Configuration{Prototypes: &config.MechanismPrototypes{}},
			assert: func(t *testing.T, err error, factory *mechanismsFactory) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, factory)
				require.NotNil(t, factory.r)
				assert.Empty(t, factory.r.errorHandlers)
				assert.Empty(t, factory.r.contextualizers)
				assert.Empty(t, factory.r.finalizers)
				assert.Empty(t, factory.r.authenticators)
				assert.Empty(t, factory.r.authorizers)
			},
		},
		{
			uc: "fails",
			conf: &config.Configuration{
				Prototypes: &config.MechanismPrototypes{
					Authenticators: []config.Mechanism{
						{
							ID:   "foo",
							Type: errorhandlers.ErrorHandlerWWWAuthenticate,
						},
					},
				},
			},
			assert: func(t *testing.T, err error, _ *mechanismsFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, authenticators.ErrUnsupportedAuthenticatorType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			var (
				impl *mechanismsFactory
				ok   bool
			)

			// WHEN
			factory, err := NewMechanismFactory(tc.conf, log.Logger, nil, nil)

			// THEN
			if err == nil {
				impl, ok = factory.(*mechanismsFactory)
				require.True(t, ok)
			}

			tc.assert(t, err, impl)
		})
	}
}
