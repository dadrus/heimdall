package pathprefix

import (
	"strings"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type PathPrefix string

func (p PathPrefix) Verify(rules []config.RuleConfig) error {
	if len(p) == 0 {
		return nil
	}

	for _, rule := range rules {
		if strings.HasPrefix(rule.URL, "/") &&
			// only path is specified
			!strings.HasPrefix(rule.URL, string(p)) ||
			// patterns are specified before the path
			// There should be a better way to check it
			!strings.Contains(rule.URL, string(p)) {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"path prefix validation failed for rule ID=%s")
		}
	}

	return nil
}
