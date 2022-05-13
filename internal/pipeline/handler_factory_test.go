package pipeline

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators"
	"github.com/dadrus/heimdall/internal/pipeline/authorizers"
	"github.com/dadrus/heimdall/internal/pipeline/errorhandlers"
	"github.com/dadrus/heimdall/internal/pipeline/hydrators"
	"github.com/dadrus/heimdall/internal/pipeline/mutators"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x"
)

type mockAuthenticator struct {
	mock.Mock
}

func (m *mockAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	args := m.Called(ctx)

	if val := args.Get(0); val != nil {
		res, ok := val.(*subject.Subject)
		if !ok {
			panic("*subject.Subject expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

func (m *mockAuthenticator) WithConfig(config map[any]any) (authenticators.Authenticator, error) {
	args := m.Called(config)

	if val := args.Get(0); val != nil {
		res, ok := val.(authenticators.Authenticator)
		if !ok {
			panic("authenticators.Authenticator expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

type mockAuthorizer struct {
	mock.Mock
}

func (m *mockAuthorizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	return m.Called(ctx, sub).Error(0)
}

func (m *mockAuthorizer) WithConfig(config map[any]any) (authorizers.Authorizer, error) {
	args := m.Called(config)

	if val := args.Get(0); val != nil {
		res, ok := val.(authorizers.Authorizer)
		if !ok {
			panic("authorizers.Authorizer expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

type mockHydrator struct {
	mock.Mock
}

func (m *mockHydrator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	return m.Called(ctx, sub).Error(0)
}

func (m *mockHydrator) WithConfig(config map[any]any) (hydrators.Hydrator, error) {
	args := m.Called(config)

	if val := args.Get(0); val != nil {
		res, ok := val.(hydrators.Hydrator)
		if !ok {
			panic("hydrators.Hydrator expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

type mockMutator struct {
	mock.Mock
}

func (m *mockMutator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	return m.Called(ctx, sub).Error(0)
}

func (m *mockMutator) WithConfig(config map[any]any) (mutators.Mutator, error) {
	args := m.Called(config)

	if val := args.Get(0); val != nil {
		res, ok := val.(mutators.Mutator)
		if !ok {
			panic("mutators.Mutator expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

type mockErrorHandler struct {
	mock.Mock
}

func (m *mockErrorHandler) Execute(ctx heimdall.Context, err error) (bool, error) {
	args := m.Called(ctx, err)

	return args.Bool(0), args.Error(0)
}

func (m *mockErrorHandler) WithConfig(config map[any]any) (errorhandlers.ErrorHandler, error) {
	args := m.Called(config)

	if val := args.Get(0); val != nil {
		res, ok := val.(errorhandlers.ErrorHandler)
		if !ok {
			panic("errorhandlers.ErrorHandler expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

func TestHandlerFactoryCreateAuthenticator(t *testing.T) {
	t.Parallel()

	ID := "foo"

	for _, tc := range []struct {
		uc            string
		id            string
		conf          any
		configureMock func(t *testing.T, mAuth *mockAuthenticator)
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
			uc:   "with bad config type",
			conf: "hi Foo",
			assert: func(t *testing.T, err error, auth authenticators.Authenticator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrAuthenticatorCreation)
				assert.Contains(t, err.Error(), "expected type")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[any]any{"foo": "bar"},
			configureMock: func(t *testing.T, mAuth *mockAuthenticator) {
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
			conf: map[any]any{"foo": "bar"},
			configureMock: func(t *testing.T, mAuth *mockAuthenticator) {
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
				func(t *testing.T, mAuth *mockAuthenticator) { t.Helper() })

			mAuth := &mockAuthenticator{}
			configureMock(t, mAuth)

			factory := &handlerFactory{
				r: &handlerPrototypeRepository{
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
		conf          any
		configureMock func(t *testing.T, mAuth *mockAuthorizer)
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
			uc:   "with bad config type",
			conf: "hi Foo",
			assert: func(t *testing.T, err error, auth authorizers.Authorizer) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrAuthorizerCreation)
				assert.Contains(t, err.Error(), "expected type")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[any]any{"foo": "bar"},
			configureMock: func(t *testing.T, mAuth *mockAuthorizer) {
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
			conf: map[any]any{"foo": "bar"},
			configureMock: func(t *testing.T, mAuth *mockAuthorizer) {
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
				func(t *testing.T, mAuth *mockAuthorizer) { t.Helper() })

			mAuth := &mockAuthorizer{}
			configureMock(t, mAuth)

			factory := &handlerFactory{
				r: &handlerPrototypeRepository{
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
		conf          any
		configureMock func(t *testing.T, mHydr *mockHydrator)
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
			uc:   "with bad config type",
			conf: "hi Foo",
			assert: func(t *testing.T, err error, hydrator hydrators.Hydrator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrHydratorCreation)
				assert.Contains(t, err.Error(), "expected type")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[any]any{"foo": "bar"},
			configureMock: func(t *testing.T, mHydr *mockHydrator) {
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
			conf: map[any]any{"foo": "bar"},
			configureMock: func(t *testing.T, mHydr *mockHydrator) {
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
				func(t *testing.T, mHydr *mockHydrator) { t.Helper() })

			mHydr := &mockHydrator{}
			configureMock(t, mHydr)

			factory := &handlerFactory{
				r: &handlerPrototypeRepository{
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
		conf          any
		configureMock func(t *testing.T, mMut *mockMutator)
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
			uc:   "with bad config type",
			conf: "hi Foo",
			assert: func(t *testing.T, err error, mutator mutators.Mutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrMutatorCreation)
				assert.Contains(t, err.Error(), "expected type")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[any]any{"foo": "bar"},
			configureMock: func(t *testing.T, mMut *mockMutator) {
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
			conf: map[any]any{"foo": "bar"},
			configureMock: func(t *testing.T, mMut *mockMutator) {
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
				func(t *testing.T, mMut *mockMutator) { t.Helper() })

			mMut := &mockMutator{}
			configureMock(t, mMut)

			factory := &handlerFactory{
				r: &handlerPrototypeRepository{
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
		conf          any
		configureMock func(t *testing.T, mEH *mockErrorHandler)
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
			uc:   "with bad config type",
			conf: "hi Foo",
			assert: func(t *testing.T, err error, errorHandler errorhandlers.ErrorHandler) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrErrorHandlerCreation)
				assert.Contains(t, err.Error(), "expected type")
			},
		},
		{
			uc:   "with failing creation from prototype",
			conf: map[any]any{"foo": "bar"},
			configureMock: func(t *testing.T, mEH *mockErrorHandler) {
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
			conf: map[any]any{"foo": "bar"},
			configureMock: func(t *testing.T, mEH *mockErrorHandler) {
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
				func(t *testing.T, mEH *mockErrorHandler) { t.Helper() })

			mEH := &mockErrorHandler{}
			configureMock(t, mEH)

			factory := &handlerFactory{
				r: &handlerPrototypeRepository{
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
		conf   config.Configuration
		assert func(t *testing.T, err error, factory *handlerFactory)
	}{
		{
			uc:   "successful",
			conf: config.Configuration{Pipeline: config.PipelineConfig{}},
			assert: func(t *testing.T, err error, factory *handlerFactory) {
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
			conf: config.Configuration{Pipeline: config.PipelineConfig{
				Authenticators: []config.PipelineObject{
					{
						ID:   "foo",
						Type: config.POTWWWAuthenticate,
					},
				},
			}},
			assert: func(t *testing.T, err error, factory *handlerFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, authenticators.ErrUnsupportedAuthenticatorType)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			var (
				impl *handlerFactory
				ok   bool
			)

			// WHEN
			factory, err := NewHandlerFactory(tc.conf, log.Logger)

			// THEN
			if err == nil {
				impl, ok = factory.(*handlerFactory)
				require.True(t, ok)
			}

			tc.assert(t, err, impl)
		})
	}
}
