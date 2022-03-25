package extractors

import (
	"errors"
	"strings"

	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type QueryParameterExtractStrategy struct {
	Name   string
	Prefix string
}

func (es QueryParameterExtractStrategy) GetAuthData(s interfaces.AuthDataSource) (string, error) {
	if val := s.Query(es.Name); len(val) != 0 {
		return strings.TrimSpace(strings.TrimPrefix(val, es.Prefix)), nil
	} else {
		return "", errors.New("no authentication data present")
	}
}
