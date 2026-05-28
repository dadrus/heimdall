package validate

import (
	"context"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/secrets"
)

type noopRepository struct{}

func (noopRepository) FindRule(_ pipeline.Context) (rule.Rule, error) {
	return nil, errFunctionNotSupported
}
func (noopRepository) AddRuleSet(_ context.Context, _ rule.RuleSet, _ []rule.Rule) error { return nil }
func (noopRepository) UpdateRuleSet(_ context.Context, _ rule.RuleSet, _ []rule.Rule) error {
	return errFunctionNotSupported
}

func (noopRepository) DeleteRuleSet(_ context.Context, _ rule.RuleSet) error {
	return errFunctionNotSupported
}

type noopRegistry struct{}

func (noopRegistry) Notify(_ secrets.Reference) {}
func (noopRegistry) Keys() []jose.JSONWebKey    { return nil }
