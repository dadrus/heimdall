package cloudblob

import (
	"context"
	"time"

	"github.com/dadrus/heimdall/internal/config"
)

type RuleSet struct {
	Rules   []config.RuleConfig
	Hash    []byte
	Key     string
	ModTime time.Time
}

type RuleSetFetcher interface {
	FetchRuleSets(ctx context.Context) ([]RuleSet, error)
	ID() string
}
