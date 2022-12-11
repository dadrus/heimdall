package mocks

import (
	"github.com/dadrus/heimdall/internal/rules/pipeline/errorhandlers"
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type MockErrorHandler struct {
	mock.Mock
}

func (m *MockErrorHandler) Execute(ctx heimdall.Context, err error) (bool, error) {
	args := m.Called(ctx, err)

	return args.Bool(0), args.Error(0)
}

func (m *MockErrorHandler) WithConfig(config map[string]any) (errorhandlers.ErrorHandler, error) {
	args := m.Called(config)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(errorhandlers.ErrorHandler), nil
	}

	return nil, args.Error(1)
}
