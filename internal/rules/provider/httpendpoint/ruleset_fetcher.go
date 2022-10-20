package httpendpoint

import (
	"context"

	"github.com/dadrus/heimdall/internal/config"
)

type RuleSetFetcher interface {
	FetchRuleSet(ctx context.Context) ([]config.RuleConfig, error)
	ID() string
}
