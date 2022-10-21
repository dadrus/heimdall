package rules

import "context"

type ruleSetDefinitionLoader interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}
