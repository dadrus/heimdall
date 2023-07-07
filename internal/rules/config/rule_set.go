package config

import (
	"strings"
	"time"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type MetaData struct {
	Hash    []byte    `json:"-" yaml:"-"`
	Source  string    `json:"-" yaml:"-"`
	ModTime time.Time `json:"-" yaml:"-"`
}

type RuleSet struct {
	MetaData

	Version string `json:"version" yaml:"version"`
	Name    string `json:"name"    yaml:"name"`
	Rules   []Rule `json:"rules"   yaml:"rules"`
}

func (rs RuleSet) VerifyPathPrefix(prefix string) error {
	for _, rule := range rs.Rules {
		if strings.HasPrefix(rule.RuleMatcher.URL, "/") &&
			// only path is specified
			!strings.HasPrefix(rule.RuleMatcher.URL, prefix) ||
			// patterns are specified before the path
			// There should be a better way to check it
			!strings.Contains(rule.RuleMatcher.URL, prefix) {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"path prefix validation failed for rule ID=%s")
		}
	}

	return nil
}
