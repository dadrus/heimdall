package authenticators

import (
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type AuthDataGetter interface {
	GetAuthData(s handler.AuthDataSource) (string, error)
}
