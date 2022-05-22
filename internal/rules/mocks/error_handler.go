package mocks

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type MockErrorHandler struct {
	mock.Mock
}

func (m *MockErrorHandler) Execute(ctx heimdall.Context, e error) (bool, error) {
	args := m.Called(ctx, e)

	return args.Bool(0), args.Error(1)
}
