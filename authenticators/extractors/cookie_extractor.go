package extractors

import (
	"errors"
	"strings"
)

type CookieExtractor string

func (e CookieExtractor) Extract(s AuthDataSource) (string, error) {
	if val := s.Cookie(strings.TrimSpace(string(e))); len(val) != 0 {
		return val, nil
	} else {
		return "", errors.New("no auth data present")
	}
}
