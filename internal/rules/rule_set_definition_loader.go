package rules

type ruleSetDefinitionLoader interface {
	Start() error
	Stop() error
}
