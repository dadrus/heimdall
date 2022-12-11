package mocks

import (
	"github.com/dadrus/heimdall/internal/rules/pipeline/authenticators"
	"github.com/dadrus/heimdall/internal/rules/pipeline/subject"
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type MockAuthenticator struct {
	mock.Mock
}

func (m *MockAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	args := m.Called(ctx)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(*subject.Subject), nil
	}

	return nil, args.Error(1)
}

func (m *MockAuthenticator) WithConfig(config map[string]any) (authenticators.Authenticator, error) {
	args := m.Called(config)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(authenticators.Authenticator), nil
	}

	return nil, args.Error(1)
}

func (m *MockAuthenticator) IsFallbackOnErrorAllowed() bool {
	return m.Called().Bool(0)
}
