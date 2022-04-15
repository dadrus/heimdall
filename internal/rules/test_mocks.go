package rules

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type mockSubjectCreator struct {
	mock.Mock
}

func (a *mockSubjectCreator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	args := a.Called(ctx)

	if val := args.Get(0); val != nil {
		res, ok := val.(*subject.Subject)
		if !ok {
			panic("*subject.Subject expected")
		}

		return res, args.Error(1)
	}

	return nil, args.Error(1)
}

type mockErrorHandler struct {
	mock.Mock
}

func (m *mockErrorHandler) Execute(ctx heimdall.Context, e error) (bool, error) {
	args := m.Called(ctx, e)

	return args.Bool(0), args.Error(1)
}
