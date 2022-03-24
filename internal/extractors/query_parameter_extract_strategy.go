package extractors

import (
	"errors"
	"strings"

	"github.com/dadrus/heimdall/internal/pipeline"
)

type QueryParameterExtractStrategy struct {
	Name   string
	Prefix string
}

func (es QueryParameterExtractStrategy) GetAuthData(s pipeline.AuthDataSource) (string, error) {
	if val := s.Query(es.Name); len(val) != 0 {
		return strings.TrimSpace(strings.TrimPrefix(val, es.Prefix)), nil
	} else {
		return "", errors.New("no authentication data present")
	}
}
