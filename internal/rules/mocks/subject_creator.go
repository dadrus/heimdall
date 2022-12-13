package mocks

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type MockSubjectCreator struct {
	mock.Mock
}

func (a *MockSubjectCreator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	args := a.Called(ctx)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(*subject.Subject), nil
	}

	return nil, args.Error(1)
}

func (a *MockSubjectCreator) IsFallbackOnErrorAllowed() bool {
	return a.Called().Bool(0)
}
