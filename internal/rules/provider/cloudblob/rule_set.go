package cloudblob

import (
	"time"

	"github.com/dadrus/heimdall/internal/rules/rule"
)

type RuleSet struct {
	Rules   []rule.Configuration
	Hash    []byte
	Key     string
	ModTime time.Time
}
