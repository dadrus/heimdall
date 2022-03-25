package extractors

import (
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type AuthDataExtractStrategy interface {
	GetAuthData(s interfaces.AuthDataSource) (string, error)
}
