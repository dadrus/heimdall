package authenticators

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
)

type AuthDataForwardStrategy interface {
	Apply(src extractors.AuthData, req *http.Request)
}
