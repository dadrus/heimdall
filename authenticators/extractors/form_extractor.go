package extractors

import (
	"errors"
	"strings"
)

type PostFormExtractor string

func (e PostFormExtractor) Extract(s AuthDataSource) (string, error) {
	if val := s.Form(strings.TrimSpace(string(e))); len(val) != 0 {
		return val, nil
	} else {
		return "", errors.New("no auth data present")
	}
}
