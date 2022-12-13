package mocks

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/unifiers"
)

type MockUnifier struct {
	mock.Mock
}

func (m *MockUnifier) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	return m.Called(ctx, sub).Error(0)
}

func (m *MockUnifier) WithConfig(config map[string]any) (unifiers.Unifier, error) {
	args := m.Called(config)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(unifiers.Unifier), nil
	}

	return nil, args.Error(1)
}
