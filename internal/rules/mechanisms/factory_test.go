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
	mocks2 "github.com/dadrus/heimdall/internal/rules/mechanisms/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/unifiers"
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
			assert: func(t *testing.T, err error, auth authenticators.Authenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrAuthenticatorCreation)
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
			assert: func(t *testing.T, err error, auth authenticators.Authenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrAuthenticatorCreation)
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
				func(t *testing.T, mAuth *mocks.AuthenticatorMock) { t.Helper() })

			mAuth := mocks.NewAuthenticatorMock(t)
			configureMock(t, mAuth)

			factory := &mechanismsFactory{
				r: &prototypeRepository{
					authenticators: map[string]authenticators.Authenticator{
						ID: mAuth,
					},
				},
			}

			id := x.IfThenElse(len(tc.id) != 0, tc.id, ID)

			// WHEN
			auth, err := factory.CreateAuthenticator(id, tc.conf)

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
			assert: func(t *testing.T, err error, auth authorizers.Authorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrAuthorizerCreation)
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
			assert: func(t *testing.T, err error, auth authorizers.Authorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrAuthorizerCreation)
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
				func(t *testing.T, mAuth *mocks3.AuthorizerMock) { t.Helper() })

			mAuth := mocks3.NewAuthorizerMock(t)
			configureMock(t, mAuth)

			factory := &mechanismsFactory{
				r: &prototypeRepository{
					authorizers: map[string]authorizers.Authorizer{
						ID: mAuth,
					},
				},
			}

			id := x.IfThenElse(len(tc.id) != 0, tc.id, ID)

			// WHEN
			auth, err := factory.CreateAuthorizer(id, tc.conf)

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
			assert: func(t *testing.T, err error, contextualizer contextualizers.Contextualizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrContextualizerCreation)
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
			assert: func(t *testing.T, err error, contextualizer contextualizers.Contextualizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrContextualizerCreation)
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
				func(t *testing.T, mHydr *mocks4.ContextualizerMock) { t.Helper() })

			mContextualizer := mocks4.NewContextualizerMock(t)
			configureMock(t, mContextualizer)

			factory := &mechanismsFactory{
				r: &prototypeRepository{
					contextualizers: map[string]contextualizers.Contextualizer{
						ID: mContextualizer,
					},
				},
			}

			id := x.IfThenElse(len(tc.id) != 0, tc.id, ID)

			// WHEN
			contextualizer, err := factory.CreateContextualizer(id, tc.conf)

			// THEN
			tc.assert(t, err, contextualizer)
		})
	}
}

func TestHandlerFactoryCreateUnifier(t *testing.T) {
	t.Parallel()

	ID := "foo"

	for _, tc := range []struct {
		uc            string
		id            string
		conf          map[string]any
		configureMock func(t *testing.T, mUn *mocks2.MockUnifier)
		assert        func(t *testing.T, err error, unifier unifiers.Unifier)
	}{
		{
			uc: "no unifier for given id",
			id: "bar",
			assert: func(t *testing.T, err error, unifier unifiers.Unifier) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnifierCreation)
				assert.Contains(t, err.Error(), "no unifier prototype")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mUn *mocks2.MockUnifier) {
				t.Helper()

				mUn.On("WithConfig", mock.Anything).Return(nil, heimdall.ErrArgument)
			},
			assert: func(t *testing.T, err error, unifier unifiers.Unifier) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnifierCreation)
				assert.Contains(t, err.Error(), heimdall.ErrArgument.Error())
			},
		},
		{
			uc:   "successful creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mUn *mocks2.MockUnifier) {
				t.Helper()

				mUn.On("WithConfig", mock.Anything).Return(mUn, nil)
			},
			assert: func(t *testing.T, err error, unifier unifiers.Unifier) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, unifier)
			},
		},
		{
			uc: "successful creation with empty config",
			assert: func(t *testing.T, err error, unifier unifiers.Unifier) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, unifier)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMock := x.IfThenElse(tc.configureMock != nil,
				tc.configureMock,
				func(t *testing.T, mUn *mocks2.MockUnifier) { t.Helper() })

			mUn := &mocks2.MockUnifier{}
			configureMock(t, mUn)

			factory := &mechanismsFactory{
				r: &prototypeRepository{
					unifiers: map[string]unifiers.Unifier{
						ID: mUn,
					},
				},
			}

			id := x.IfThenElse(len(tc.id) != 0, tc.id, ID)

			// WHEN
			unifier, err := factory.CreateUnifier(id, tc.conf)

			// THEN
			tc.assert(t, err, unifier)
			mUn.AssertExpectations(t)
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
		configureMock func(t *testing.T, mEH *mocks2.MockErrorHandler)
		assert        func(t *testing.T, err error, errorHandler errorhandlers.ErrorHandler)
	}{
		{
			uc: "no error handler for given id",
			id: "bar",
			assert: func(t *testing.T, err error, errorHandler errorhandlers.ErrorHandler) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrErrorHandlerCreation)
				assert.Contains(t, err.Error(), "no error handler prototype")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mEH *mocks2.MockErrorHandler) {
				t.Helper()

				mEH.On("WithConfig", mock.Anything).Return(nil, heimdall.ErrArgument)
			},
			assert: func(t *testing.T, err error, errorHandler errorhandlers.ErrorHandler) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrErrorHandlerCreation)
				assert.Contains(t, err.Error(), heimdall.ErrArgument.Error())
			},
		},
		{
			uc:   "successful creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mEH *mocks2.MockErrorHandler) {
				t.Helper()

				mEH.On("WithConfig", mock.Anything).Return(mEH, nil)
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
				func(t *testing.T, mEH *mocks2.MockErrorHandler) { t.Helper() })

			mEH := &mocks2.MockErrorHandler{}
			configureMock(t, mEH)

			factory := &mechanismsFactory{
				r: &prototypeRepository{
					errorHandlers: map[string]errorhandlers.ErrorHandler{
						ID: mEH,
					},
				},
			}

			id := x.IfThenElse(len(tc.id) != 0, tc.id, ID)

			// WHEN
			errorHandler, err := factory.CreateErrorHandler(id, tc.conf)

			// THEN
			tc.assert(t, err, errorHandler)
			mEH.AssertExpectations(t)
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
			conf: &config.Configuration{Rules: config.Rules{Prototypes: &config.MechanismPrototypes{}}},
			assert: func(t *testing.T, err error, factory *mechanismsFactory) {
				t.Helper()

				assert.NoError(t, err)
				require.NotNil(t, factory)
				require.NotNil(t, factory.r)
				assert.Empty(t, factory.r.errorHandlers)
				assert.Empty(t, factory.r.contextualizers)
				assert.Empty(t, factory.r.unifiers)
				assert.Empty(t, factory.r.authenticators)
				assert.Empty(t, factory.r.authorizers)
			},
		},
		{
			uc: "fails",
			conf: &config.Configuration{
				Rules: config.Rules{
					Prototypes: &config.MechanismPrototypes{
						Authenticators: []config.Mechanism{
							{
								ID:   "foo",
								Type: errorhandlers.ErrorHandlerWWWAuthenticate,
							},
						},
					},
				},
			},
			assert: func(t *testing.T, err error, factory *mechanismsFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, authenticators.ErrUnsupportedAuthenticatorType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			var (
				impl *mechanismsFactory
				ok   bool
			)

			// WHEN
			factory, err := NewFactory(tc.conf, log.Logger)

			// THEN
			if err == nil {
				impl, ok = factory.(*mechanismsFactory)
				require.True(t, ok)
			}

			tc.assert(t, err, impl)
		})
	}
}
