package authenticators

import "github.com/dadrus/heimdall/internal/pipeline"

type AuthDataGetter interface {
	GetAuthData(s pipeline.AuthDataSource) (string, error)
}
