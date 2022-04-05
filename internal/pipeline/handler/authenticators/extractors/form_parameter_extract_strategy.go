package extractors

import (
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type FormParameterExtractStrategy struct {
	Name   string
	Prefix string
}

func (es FormParameterExtractStrategy) GetAuthData(s heimdall.Context) (string, error) {
	if val := s.RequestFormParameter(es.Name); len(val) != 0 {
		return strings.TrimSpace(strings.TrimPrefix(val, es.Prefix)), nil
	}

	return "", errorchain.NewWithMessagef(ErrAuthData, "no '%s' form parameter present", es.Name)
}
