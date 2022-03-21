package extractors

import (
	"strings"

	"github.com/dadrus/heimdall/authenticators"
)

type QueryExtractor string

func (qe QueryExtractor) Extract(s authenticators.AuthDataSource) (string, error) {
	if val := s.Query(strings.TrimSpace(string(qe))); len(val) != 0 {
		return val, nil
	} else {
		return "", ErrNoAuthDataPresent
	}
}
