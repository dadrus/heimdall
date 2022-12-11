package mocks

import (
	"github.com/dadrus/heimdall/internal/rules/pipeline/subject"
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type MockSubjectHandler struct {
	mock.Mock
}

func (a *MockSubjectHandler) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	return a.Called(ctx, sub).Error(0)
}
