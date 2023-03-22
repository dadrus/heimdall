package rule

//go:generate mockery --name SetProcessor --structname RuleSetProcessorMock

type SetProcessor interface {
	OnCreated(ruleSet *SetConfiguration)
	OnUpdated(ruleSet *SetConfiguration)
	OnDeleted(ruleSet *SetConfiguration)
}
