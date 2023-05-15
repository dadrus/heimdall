package authenticators

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
)

type DefaultForwardStrategy struct{}

func (s DefaultForwardStrategy) Apply(src extractors.AuthData, req *http.Request) { src.ApplyTo(req) }
