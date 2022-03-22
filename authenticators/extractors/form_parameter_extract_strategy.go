package extractors

import (
	"strings"

	"github.com/dadrus/heimdall/authenticators"
)

type FormParameterExtractStrategy struct {
	Name   string
	Prefix string
}

func (es FormParameterExtractStrategy) GetAuthData(s authenticators.AuthDataSource) (string, error) {
	if val := s.Form(es.Name); len(val) != 0 {
		return strings.TrimSpace(strings.TrimPrefix(val, es.Prefix)), nil
	} else {
		return "", ErrNoAuthDataPresent
	}
}
