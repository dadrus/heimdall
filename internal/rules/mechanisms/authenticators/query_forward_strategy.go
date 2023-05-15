package authenticators

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
)

type QueryForwardStrategy struct {
	Name string `mapstructure:"name"`
}

func (s *QueryForwardStrategy) Apply(src extractors.AuthData, req *http.Request) {
	query := req.URL.Query()
	query.Add(s.Name, src.Value())
	req.URL.RawQuery = query.Encode()
}
