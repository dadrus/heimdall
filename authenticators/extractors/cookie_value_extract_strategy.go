package extractors

import (
	"strings"

	"github.com/dadrus/heimdall/authenticators"
)

type CookieValueExtractStrategy struct {
	Name   string
	Prefix string
}

func (es CookieValueExtractStrategy) GetAuthData(s authenticators.AuthDataSource) (string, error) {
	if val := s.Cookie(es.Name); len(val) != 0 {
		return strings.TrimSpace(strings.TrimPrefix(val, es.Prefix)), nil
	} else {
		return "", ErrNoAuthDataPresent
	}
}
