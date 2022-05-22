package mocks

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/hydrators"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
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
