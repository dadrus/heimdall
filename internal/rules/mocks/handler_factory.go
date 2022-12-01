package mocks

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators"
	"github.com/dadrus/heimdall/internal/pipeline/authorizers"
	"github.com/dadrus/heimdall/internal/pipeline/errorhandlers"
	"github.com/dadrus/heimdall/internal/pipeline/hydrators"
	"github.com/dadrus/heimdall/internal/pipeline/mutators"
)

type MockHandlerFactory struct {
	mock.Mock
}

func (m *MockHandlerFactory) CreateAuthenticator(id string, conf config.MechanismConfig) (
	authenticators.Authenticator, error,
) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(authenticators.Authenticator), nil
	}

	return nil, args.Error(1)
}

func (m *MockHandlerFactory) CreateAuthorizer(id string, conf config.MechanismConfig) (
	authorizers.Authorizer, error,
) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(authorizers.Authorizer), nil
	}

	return nil, args.Error(1)
}

func (m *MockHandlerFactory) CreateHydrator(id string, conf config.MechanismConfig) (
	hydrators.Hydrator, error,
) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(hydrators.Hydrator), nil
	}

	return nil, args.Error(1)
}

func (m *MockHandlerFactory) CreateMutator(id string, conf config.MechanismConfig) (
	mutators.Mutator, error,
) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(mutators.Mutator), nil
	}

	return nil, args.Error(1)
}

func (m *MockHandlerFactory) CreateErrorHandler(id string, conf config.MechanismConfig) (
	errorhandlers.ErrorHandler, error,
) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(errorhandlers.ErrorHandler), nil
	}

	return nil, args.Error(1)
}
