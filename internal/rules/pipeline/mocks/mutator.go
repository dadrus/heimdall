package mocks

import (
	"github.com/dadrus/heimdall/internal/rules/pipeline/mutators"
	"github.com/dadrus/heimdall/internal/rules/pipeline/subject"
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type MockMutator struct {
	mock.Mock
}

func (m *MockMutator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	return m.Called(ctx, sub).Error(0)
}

func (m *MockMutator) WithConfig(config map[string]any) (mutators.Mutator, error) {
	args := m.Called(config)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(mutators.Mutator), nil
	}

	return nil, args.Error(1)
}
