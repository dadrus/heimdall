package httpendpoint

import "github.com/dadrus/heimdall/internal/config"

type RuleSet struct {
	Rules []config.RuleConfig
	Hash  []byte
}
