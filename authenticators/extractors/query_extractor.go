package extractors

import (
	"errors"
	"strings"
)

type QueryExtractor string

func (qe QueryExtractor) Extract(s AuthDataSource) (string, error) {
	if val := s.Query(strings.TrimSpace(string(qe))); len(val) != 0 {
		return val, nil
	} else {
		return "", errors.New("no auth data present")
	}
}
