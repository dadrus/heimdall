package rule

import "github.com/dadrus/heimdall/internal/rules/config"

//go:generate mockery --name SetProcessor --structname RuleSetProcessorMock

type SetProcessor interface {
	OnCreated(ruleSet *config.RuleSet)
	OnUpdated(ruleSet *config.RuleSet)
	OnDeleted(ruleSet *config.RuleSet)
}
