package extractors

import (
	"strings"

	"github.com/dadrus/heimdall/authenticators"
)

type CookieExtractor string

func (e CookieExtractor) Extract(s authenticators.AuthDataSource) (string, error) {
	if val := s.Cookie(strings.TrimSpace(string(e))); len(val) != 0 {
		return val, nil
	} else {
		return "", ErrNoAuthDataPresent
	}
}
