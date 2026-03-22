package rules

import "go.opentelemetry.io/otel/attribute"

const (
	stepIDKey          = attribute.Key("step.id")
	mechanismNameKey   = attribute.Key("mechanism.name")
	mechanismKindKey   = attribute.Key("mechanism.kind")
	ruleIDKey          = attribute.Key("rule.id")
	ruleSetIDKey       = attribute.Key("ruleset.id")
	ruleSetNameKey     = attribute.Key("ruleset.name")
	ruleSetProviderKey = attribute.Key("provider")
)
