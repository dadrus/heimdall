package httpendpoint

import (
	"context"
)

type RuleSetFetcher interface {
	FetchRuleSet(ctx context.Context) (*RuleSet, error)
	ID() string
}
