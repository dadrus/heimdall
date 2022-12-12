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
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authorizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/hydrators"
	mocks2 "github.com/dadrus/heimdall/internal/rules/mechanisms/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/mutators"
	"github.com/dadrus/heimdall/internal/x"
)

func TestHandlerFactoryCreateAuthenticator(t *testing.T) {
	t.Parallel()

	ID := "foo"

	for _, tc := range []struct {
		uc            string
		id            string
		conf          map[string]any
		configureMock func(t *testing.T, mAuth *mocks2.MockAuthenticator)
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
			configureMock: func(t *testing.T, mAuth *mocks2.MockAuthenticator) {
				t.Helper()

				mAuth.On("WithConfig", mock.Anything).Return(nil, heimdall.ErrArgument)
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
			configureMock: func(t *testing.T, mAuth *mocks2.MockAuthenticator) {
				t.Helper()

				mAuth.On("WithConfig", mock.Anything).Return(mAuth, nil)
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
				func(t *testing.T, mAuth *mocks2.MockAuthenticator) { t.Helper() })

			mAuth := &mocks2.MockAuthenticator{}
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
			mAuth.AssertExpectations(t)
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
		configureMock func(t *testing.T, mAuth *mocks2.MockAuthorizer)
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
			configureMock: func(t *testing.T, mAuth *mocks2.MockAuthorizer) {
				t.Helper()

				mAuth.On("WithConfig", mock.Anything).Return(nil, heimdall.ErrArgument)
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
			configureMock: func(t *testing.T, mAuth *mocks2.MockAuthorizer) {
				t.Helper()

				mAuth.On("WithConfig", mock.Anything).Return(mAuth, nil)
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
				func(t *testing.T, mAuth *mocks2.MockAuthorizer) { t.Helper() })

			mAuth := &mocks2.MockAuthorizer{}
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
			mAuth.AssertExpectations(t)
		})
	}
}

func TestHandlerFactoryCreateHydrator(t *testing.T) {
	t.Parallel()

	ID := "foo"

	for _, tc := range []struct {
		uc            string
		id            string
		conf          map[string]any
		configureMock func(t *testing.T, mHydr *mocks2.MockHydrator)
		assert        func(t *testing.T, err error, hydrator hydrators.Hydrator)
	}{
		{
			uc: "no hydrator for given id",
			id: "bar",
			assert: func(t *testing.T, err error, hydrator hydrators.Hydrator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrHydratorCreation)
				assert.Contains(t, err.Error(), "no hydrator prototype")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mHydr *mocks2.MockHydrator) {
				t.Helper()

				mHydr.On("WithConfig", mock.Anything).Return(nil, heimdall.ErrArgument)
			},
			assert: func(t *testing.T, err error, hydrator hydrators.Hydrator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrHydratorCreation)
				assert.Contains(t, err.Error(), heimdall.ErrArgument.Error())
			},
		},
		{
			uc:   "successful creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mHydr *mocks2.MockHydrator) {
				t.Helper()

				mHydr.On("WithConfig", mock.Anything).Return(mHydr, nil)
			},
			assert: func(t *testing.T, err error, hydrator hydrators.Hydrator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, hydrator)
			},
		},
		{
			uc: "successful creation with empty config",
			assert: func(t *testing.T, err error, hydrator hydrators.Hydrator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, hydrator)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMock := x.IfThenElse(tc.configureMock != nil,
				tc.configureMock,
				func(t *testing.T, mHydr *mocks2.MockHydrator) { t.Helper() })

			mHydr := &mocks2.MockHydrator{}
			configureMock(t, mHydr)

			factory := &mechanismsFactory{
				r: &prototypeRepository{
					hydrators: map[string]hydrators.Hydrator{
						ID: mHydr,
					},
				},
			}

			id := x.IfThenElse(len(tc.id) != 0, tc.id, ID)

			// WHEN
			hydrator, err := factory.CreateHydrator(id, tc.conf)

			// THEN
			tc.assert(t, err, hydrator)
			mHydr.AssertExpectations(t)
		})
	}
}

func TestHandlerFactoryCreateMutator(t *testing.T) {
	t.Parallel()

	ID := "foo"

	for _, tc := range []struct {
		uc            string
		id            string
		conf          map[string]any
		configureMock func(t *testing.T, mMut *mocks2.MockMutator)
		assert        func(t *testing.T, err error, mutator mutators.Mutator)
	}{
		{
			uc: "no mutator for given id",
			id: "bar",
			assert: func(t *testing.T, err error, mutator mutators.Mutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrMutatorCreation)
				assert.Contains(t, err.Error(), "no mutator prototype")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mMut *mocks2.MockMutator) {
				t.Helper()

				mMut.On("WithConfig", mock.Anything).Return(nil, heimdall.ErrArgument)
			},
			assert: func(t *testing.T, err error, mutator mutators.Mutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrMutatorCreation)
				assert.Contains(t, err.Error(), heimdall.ErrArgument.Error())
			},
		},
		{
			uc:   "successful creation from prototype",
			conf: map[string]any{"foo": "bar"},
			configureMock: func(t *testing.T, mMut *mocks2.MockMutator) {
				t.Helper()

				mMut.On("WithConfig", mock.Anything).Return(mMut, nil)
			},
			assert: func(t *testing.T, err error, mutator mutators.Mutator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, mutator)
			},
		},
		{
			uc: "successful creation with empty config",
			assert: func(t *testing.T, err error, mutator mutators.Mutator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, mutator)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMock := x.IfThenElse(tc.configureMock != nil,
				tc.configureMock,
				func(t *testing.T, mMut *mocks2.MockMutator) { t.Helper() })

			mMut := &mocks2.MockMutator{}
			configureMock(t, mMut)

			factory := &mechanismsFactory{
				r: &prototypeRepository{
					mutators: map[string]mutators.Mutator{
						ID: mMut,
					},
				},
			}

			id := x.IfThenElse(len(tc.id) != 0, tc.id, ID)

			// WHEN
			mutatos, err := factory.CreateMutator(id, tc.conf)

			// THEN
			tc.assert(t, err, mutatos)
			mMut.AssertExpectations(t)
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
			conf: &config.Configuration{Rules: config.RulesConfig{Prototypes: &config.MechanismPrototypes{}}},
			assert: func(t *testing.T, err error, factory *mechanismsFactory) {
				t.Helper()

				assert.NoError(t, err)
				require.NotNil(t, factory)
				require.NotNil(t, factory.r)
				assert.Empty(t, factory.r.errorHandlers)
				assert.Empty(t, factory.r.hydrators)
				assert.Empty(t, factory.r.mutators)
				assert.Empty(t, factory.r.authenticators)
				assert.Empty(t, factory.r.authorizers)
			},
		},
		{
			uc: "fails",
			conf: &config.Configuration{
				Rules: config.RulesConfig{
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
