package mocks

import (
	"github.com/dadrus/heimdall/internal/rules/pipeline/hydrators"
	"github.com/dadrus/heimdall/internal/rules/pipeline/subject"
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type MockHydrator struct {
	mock.Mock
}

func (m *MockHydrator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	return m.Called(ctx, sub).Error(0)
}

func (m *MockHydrator) WithConfig(config map[string]any) (hydrators.Hydrator, error) {
	args := m.Called(config)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(hydrators.Hydrator), nil
	}

	return nil, args.Error(1)
}
