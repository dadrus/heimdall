package authenticators

import (
	"fmt"
	"net/http"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
)

type HeaderForwardStrategy struct {
	Name   string `mapstructure:"name"`
	Scheme string `mapstructure:"scheme"`
}

func (s *HeaderForwardStrategy) Apply(src extractors.AuthData, req *http.Request) {
	var value string
	if len(s.Scheme) == 0 {
		value = src.Value()
	} else {
		value = fmt.Sprintf("%s %s", s.Scheme, src.Value())
	}

	req.Header.Add(s.Name, value)
}
