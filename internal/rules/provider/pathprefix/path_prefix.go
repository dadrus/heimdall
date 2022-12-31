package pathprefix

import (
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type PathPrefix string

func (p PathPrefix) Verify(rules []rule.Configuration) error {
	if len(p) == 0 {
		return nil
	}

	for _, rule := range rules {
		if strings.HasPrefix(rule.RuleMatcher.URL, "/") &&
			// only path is specified
			!strings.HasPrefix(rule.RuleMatcher.URL, string(p)) ||
			// patterns are specified before the path
			// There should be a better way to check it
			!strings.Contains(rule.RuleMatcher.URL, string(p)) {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"path prefix validation failed for rule ID=%s")
		}
	}

	return nil
}
