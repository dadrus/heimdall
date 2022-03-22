package extractors

import (
	"github.com/dadrus/heimdall/authenticators"
)

type AuthDataExtractStrategy interface {
	GetAuthData(s authenticators.AuthDataSource) (string, error)
}
