package extractors

import (
	"strings"

	"github.com/dadrus/heimdall/authenticators"
)

type HeaderExtractor struct {
	HeaderName  string
	ValuePrefix string
}

func (e HeaderExtractor) Extract(s authenticators.AuthDataSource) (string, error) {
	val := s.Header(e.HeaderName)
	if len(val) == 0 {
		return "", ErrNoAuthDataPresent
	}
	if len(e.ValuePrefix) == 0 {
		return strings.TrimSpace(val), nil
	} else if strings.Index(strings.ToLower(val), e.ValuePrefix) == -1 {
		return "", ErrNoAuthDataPresent
	}

	return strings.TrimSpace(val[len(e.ValuePrefix)+1:]), nil
}
