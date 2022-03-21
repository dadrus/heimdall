package extractors

import (
	"errors"
	"strings"
)

type HeaderExtractor struct {
	HeaderName  string
	ValuePrefix string
}

func (e HeaderExtractor) Extract(s AuthDataSource) (string, error) {
	val := s.Header(e.HeaderName)
	if len(val) == 0 {
		return "", errors.New("no auth data present")
	}
	if len(e.ValuePrefix) == 0 {
		return val, nil
	} else if strings.Index(strings.ToLower(val), e.ValuePrefix) == -1 {
		return "", errors.New("no auth data present")
	}

	return val[len(e.ValuePrefix)+1:], nil
}
