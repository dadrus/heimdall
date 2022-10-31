package cloudblob

import (
	"context"
)

type RuleSetFetcher interface {
	FetchRuleSets(ctx context.Context) ([]RuleSet, error)
	ID() string
}
