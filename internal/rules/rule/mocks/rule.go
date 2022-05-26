package mocks

import (
	"net/url"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type MockRule struct {
	mock.Mock
}

func (m *MockRule) ID() string                         { return m.Called().String(0) }
func (m *MockRule) SrcID() string                      { return m.Called().String(0) }
func (m *MockRule) Execute(ctx heimdall.Context) error { return m.Called(ctx).Error(0) }
func (m *MockRule) MatchesMethod(method string) bool   { return m.Called(method).Bool(0) }
func (m *MockRule) MatchesURL(reqURL *url.URL) bool    { return m.Called(reqURL).Bool(0) }
