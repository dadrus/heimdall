package extractors

import (
	"net/http"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type HeaderValueExtractStrategy struct {
	Name   string
	Prefix string
}

func (es HeaderValueExtractStrategy) GetAuthData(s heimdall.Context) (AuthData, error) {
	if val := s.RequestHeader(es.Name); len(val) != 0 {
		return &headerAuthData{
			name:  es.Name,
			value: strings.TrimSpace(strings.TrimPrefix(val, es.Prefix)),
		}, nil
	}

	return nil, errorchain.NewWithMessagef(heimdall.ErrArgument, "no '%s' header present", es.Name)
}

type headerAuthData struct {
	name  string
	value string
}

func (c *headerAuthData) ApplyTo(req *http.Request) {
	req.Header.Add(c.name, c.value)
}

func (c *headerAuthData) Value() string {
	return c.value
}
