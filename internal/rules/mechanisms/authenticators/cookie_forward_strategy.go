package authenticators

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
)

type CookieForwardStrategy struct {
	Name string `mapstructure:"name"`
}

func (s *CookieForwardStrategy) Apply(src extractors.AuthData, req *http.Request) {
	req.AddCookie(&http.Cookie{Name: s.Name, Value: src.Value()})
}
