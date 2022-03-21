package extractors

import "github.com/dadrus/heimdall/authenticators"

type AuthDataExtractor interface {
	Extract(s authenticators.AuthDataSource) (string, error)
}
