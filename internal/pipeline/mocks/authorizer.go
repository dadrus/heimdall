package mocks

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/authorizers"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type MockAuthorizer struct {
	mock.Mock
}

func (m *MockAuthorizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	return m.Called(ctx, sub).Error(0)
}

func (m *MockAuthorizer) WithConfig(config map[string]any) (authorizers.Authorizer, error) {
	args := m.Called(config)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(authorizers.Authorizer), nil
	}

	return nil, args.Error(1)
}
