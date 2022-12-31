package mocks

import (
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/rules/rule"
)

type MockRuleFactory struct {
	mock.Mock
}

func (m *MockRuleFactory) CreateRule(srcID string, ruleConfig rule.Configuration) (rule.Rule, error) {
	args := m.Called(srcID, ruleConfig)

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(rule.Rule), nil
	}

	return nil, args.Error(1)
}

func (m *MockRuleFactory) HasDefaultRule() bool {
	return m.Called().Bool(0)
}

func (m *MockRuleFactory) DefaultRule() rule.Rule {
	args := m.Called()

	if val := args.Get(0); val != nil {
		// nolint: forcetypeassert
		return val.(rule.Rule)
	}

	return nil
}
