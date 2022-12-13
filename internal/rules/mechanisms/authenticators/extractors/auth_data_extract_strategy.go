package extractors

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type AuthData interface {
	ApplyTo(req *http.Request)
	Value() string
}

type AuthDataExtractStrategy interface {
	GetAuthData(ctx heimdall.Context) (AuthData, error)
}
