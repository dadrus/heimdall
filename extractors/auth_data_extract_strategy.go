package extractors

import (
	"github.com/dadrus/heimdall/pipeline"
)

type AuthDataExtractStrategy interface {
	GetAuthData(s pipeline.AuthDataSource) (string, error)
}
