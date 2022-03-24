package extractors

import (
	"github.com/dadrus/heimdall/internal/pipeline"
)

type AuthDataExtractStrategy interface {
	GetAuthData(s pipeline.AuthDataSource) (string, error)
}
