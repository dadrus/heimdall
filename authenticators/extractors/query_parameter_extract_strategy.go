package extractors

import (
	"strings"

	"github.com/dadrus/heimdall/authenticators"
)

type QueryParameterExtractStrategy struct {
	Name   string
	Prefix string
}

func (es QueryParameterExtractStrategy) GetAuthData(s authenticators.AuthDataSource) (string, error) {
	if val := s.Query(es.Name); len(val) != 0 {
		return strings.TrimSpace(strings.TrimPrefix(val, es.Prefix)), nil
	} else {
		return "", ErrNoAuthDataPresent
	}
}
