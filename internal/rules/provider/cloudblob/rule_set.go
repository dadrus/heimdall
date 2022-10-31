package cloudblob

import (
	"time"

	"github.com/dadrus/heimdall/internal/config"
)

type RuleSet struct {
	Rules   []config.RuleConfig
	Hash    []byte
	Key     string
	ModTime time.Time
}
