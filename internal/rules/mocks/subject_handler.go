package mocks

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type MockSubjectHandler struct {
	mock.Mock
}

func (a *MockSubjectHandler) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	return a.Called(ctx, sub).Error(0)
}
