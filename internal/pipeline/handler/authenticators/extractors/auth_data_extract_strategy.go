package extractors

import (
	"github.com/dadrus/heimdall/internal/heimdall"
)

type AuthDataExtractStrategy interface {
	GetAuthData(ctx heimdall.Context) (string, error)
}
