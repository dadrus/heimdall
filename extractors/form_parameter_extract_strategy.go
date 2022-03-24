package extractors

import (
	"errors"
	"strings"

	"github.com/dadrus/heimdall/pipeline"
)

type FormParameterExtractStrategy struct {
	Name   string
	Prefix string
}

func (es FormParameterExtractStrategy) GetAuthData(s pipeline.AuthDataSource) (string, error) {
	if val := s.Form(es.Name); len(val) != 0 {
		return strings.TrimSpace(strings.TrimPrefix(val, es.Prefix)), nil
	} else {
		return "", errors.New("no authentication data present")
	}
}
