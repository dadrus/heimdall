package extractors

import (
	"strings"

	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CookieValueExtractStrategy struct {
	Name   string
	Prefix string
}

func (es CookieValueExtractStrategy) GetAuthData(s handler.RequestContext) (string, error) {
	if val := s.Cookie(es.Name); len(val) != 0 {
		return strings.TrimSpace(strings.TrimPrefix(val, es.Prefix)), nil
	}

	return "", errorchain.NewWithMessagef(ErrAuthData, "no '%s' cookie present", es.Name)
}
