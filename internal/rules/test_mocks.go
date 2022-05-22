package rules

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators"
	"github.com/dadrus/heimdall/internal/pipeline/authorizers"
	"github.com/dadrus/heimdall/internal/pipeline/errorhandlers"
	"github.com/dadrus/heimdall/internal/pipeline/hydrators"
	"github.com/dadrus/heimdall/internal/pipeline/mutators"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type mockSubjectCreator struct {
	mock.Mock
}

func (a *mockSubjectCreator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	args := a.Called(ctx)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(*subject.Subject), nil
	}

	return nil, args.Error(1)
}

type mockSubjectHandler struct {
	mock.Mock
}

func (a *mockSubjectHandler) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	return a.Called(ctx, sub).Error(0)
}

type mockErrorHandler struct {
	mock.Mock
}

func (m *mockErrorHandler) Execute(ctx heimdall.Context, e error) (bool, error) {
	args := m.Called(ctx, e)

	return args.Bool(0), args.Error(1)
}

type mockHandlerFactory struct {
	mock.Mock
}

func (m *mockHandlerFactory) CreateAuthenticator(id string, conf map[string]any) (authenticators.Authenticator, error) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(authenticators.Authenticator), nil
	}

	return nil, args.Error(1)
}

func (m *mockHandlerFactory) CreateAuthorizer(id string, conf map[string]any) (authorizers.Authorizer, error) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(authorizers.Authorizer), nil
	}

	return nil, args.Error(1)
}

func (m *mockHandlerFactory) CreateHydrator(id string, conf map[string]any) (hydrators.Hydrator, error) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(hydrators.Hydrator), nil
	}

	return nil, args.Error(1)
}

func (m *mockHandlerFactory) CreateMutator(id string, conf map[string]any) (mutators.Mutator, error) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(mutators.Mutator), nil
	}

	return nil, args.Error(1)
}

func (m *mockHandlerFactory) CreateErrorHandler(id string, conf map[string]any) (errorhandlers.ErrorHandler, error) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(errorhandlers.ErrorHandler), nil
	}

	return nil, args.Error(1)
}
