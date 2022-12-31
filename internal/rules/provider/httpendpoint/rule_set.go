package httpendpoint

import "github.com/dadrus/heimdall/internal/rules/rule"

type RuleSet struct {
	Rules []rule.Configuration
	Hash  []byte
}
