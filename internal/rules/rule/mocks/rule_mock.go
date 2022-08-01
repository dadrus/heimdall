package mocks

import (
	"net/url"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type MockRule struct {
	mock.Mock
}

func (m *MockRule) ID() string                       { return m.Called().String(0) }
func (m *MockRule) SrcID() string                    { return m.Called().String(0) }
func (m *MockRule) MatchesMethod(method string) bool { return m.Called(method).Bool(0) }
func (m *MockRule) MatchesURL(reqURL *url.URL) bool  { return m.Called(reqURL).Bool(0) }

func (m *MockRule) Execute(ctx heimdall.Context) (*url.URL, error) {
	args := m.Called(ctx)

	if val := args.Get(0); val != nil {
		return val.(*url.URL), nil // nolint: forcetypeassert
	}

	return nil, args.Error(1)
}
