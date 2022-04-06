package extractors

import (
	"net/http"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type QueryParameterExtractStrategy struct {
	Name string
}

func (es QueryParameterExtractStrategy) GetAuthData(s heimdall.Context) (AuthData, error) {
	if val := s.RequestQueryParameter(es.Name); len(val) != 0 {
		return &queryParameterAuthData{
			name:  es.Name,
			value: strings.TrimSpace(val),
		}, nil
	}

	return nil, errorchain.NewWithMessagef(ErrAuthData, "no '%s' query parameter present", es.Name)
}

type queryParameterAuthData struct {
	name  string
	value string
}

func (c *queryParameterAuthData) ApplyTo(req *http.Request) {
	query := req.URL.Query()
	query.Add(c.name, c.value)
	req.URL.RawQuery = query.Encode()
}

func (c *queryParameterAuthData) Value() string {
	return c.value
}
