package authenticators

import (
	"fmt"
	"net/http"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
)

type HeaderForwardStrategy struct {
	Name   string `mapstructure:"name"`
	Schema string `mapstructure:"schema"`
}

func (s *HeaderForwardStrategy) Apply(src extractors.AuthData, req *http.Request) {
	var value string
	if len(s.Schema) != 0 {
		value = src.Value()
	} else {
		value = fmt.Sprintf("%s %s", s.Schema, src.Value())
	}

	req.Header.Add(s.Name, value)
}
