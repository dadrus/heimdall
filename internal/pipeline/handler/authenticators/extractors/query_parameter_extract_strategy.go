package extractors

import (
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type QueryParameterExtractStrategy struct {
	Name   string
	Prefix string
}

func (es QueryParameterExtractStrategy) GetAuthData(s heimdall.Context) (string, error) {
	if val := s.RequestQueryParameter(es.Name); len(val) != 0 {
		return strings.TrimSpace(strings.TrimPrefix(val, es.Prefix)), nil
	}

	return "", errorchain.NewWithMessagef(ErrAuthData, "no '%s' query parameter present", es.Name)
}
