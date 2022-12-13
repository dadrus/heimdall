package mocks

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authorizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contextualizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/mutators"
)

type MockFactory struct {
	mock.Mock
}

func (m *MockFactory) CreateAuthenticator(id string, conf config.MechanismConfig) (
	authenticators.Authenticator, error,
) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(authenticators.Authenticator), nil
	}

	return nil, args.Error(1)
}

func (m *MockFactory) CreateAuthorizer(id string, conf config.MechanismConfig) (
	authorizers.Authorizer, error,
) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(authorizers.Authorizer), nil
	}

	return nil, args.Error(1)
}

func (m *MockFactory) CreateContextualizer(id string, conf config.MechanismConfig) (
	contextualizers.Contextualizer, error,
) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(contextualizers.Contextualizer), nil
	}

	return nil, args.Error(1)
}

func (m *MockFactory) CreateMutator(id string, conf config.MechanismConfig) (
	mutators.Mutator, error,
) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(mutators.Mutator), nil
	}

	return nil, args.Error(1)
}

func (m *MockFactory) CreateErrorHandler(id string, conf config.MechanismConfig) (
	errorhandlers.ErrorHandler, error,
) {
	args := m.Called(id, conf)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(errorhandlers.ErrorHandler), nil
	}

	return nil, args.Error(1)
}
