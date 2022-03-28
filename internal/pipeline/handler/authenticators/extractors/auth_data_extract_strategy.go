package extractors

import (
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type AuthDataExtractStrategy interface {
	GetAuthData(s handler.AuthDataSource) (string, error)
}
