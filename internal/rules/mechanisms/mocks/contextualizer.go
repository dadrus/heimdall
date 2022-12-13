package mocks

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contextualizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type MockContextualizer struct {
	mock.Mock
}

func (m *MockContextualizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	return m.Called(ctx, sub).Error(0)
}

func (m *MockContextualizer) WithConfig(config map[string]any) (contextualizers.Contextualizer, error) {
	args := m.Called(config)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(contextualizers.Contextualizer), nil
	}

	return nil, args.Error(1)
}
