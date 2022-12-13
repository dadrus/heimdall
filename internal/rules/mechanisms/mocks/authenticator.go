package mocks

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
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
