package mocks

import (
	"net/url"

	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/rules/rule"
)

type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) FindRule(reqURL *url.URL) (rule.Rule, error) {
	args := m.Called(reqURL)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(rule.Rule), nil
	}

	return nil, args.Error(1)
}
