package extractors

import (
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type HeaderValueExtractStrategy struct {
	Name   string
	Prefix string
}

func (es HeaderValueExtractStrategy) GetAuthData(s heimdall.Context) (string, error) {
	if val := s.RequestHeader(es.Name); len(val) != 0 {
		return strings.TrimSpace(strings.TrimPrefix(val, es.Prefix)), nil
	}

	return "", errorchain.NewWithMessagef(ErrAuthData, "no '%s' header present", es.Name)
}
