package extractors

import (
	"strings"

	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type QueryParameterExtractStrategy struct {
	Name   string
	Prefix string
}

func (es QueryParameterExtractStrategy) GetAuthData(s handler.RequestContext) (string, error) {
	if val := s.Query(es.Name); len(val) != 0 {
		return strings.TrimSpace(strings.TrimPrefix(val, es.Prefix)), nil
	}

	return "", ErrAuthData
}
