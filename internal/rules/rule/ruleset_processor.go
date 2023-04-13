package rule

import "github.com/dadrus/heimdall/internal/rules/config"

//go:generate mockery --name SetProcessor --structname RuleSetProcessorMock

type SetProcessor interface {
	OnCreated(ruleSet *config.RuleSet) error
	OnUpdated(ruleSet *config.RuleSet) error
	OnDeleted(ruleSet *config.RuleSet) error
}
