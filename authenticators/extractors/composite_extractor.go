package extractors

import (
	"github.com/dadrus/heimdall/authenticators"
)

type TokenExtractor interface {
	Extract(s authenticators.AuthDataSource) (string, error)
}

type CompositeExtractor []TokenExtractor

func (ce CompositeExtractor) Extract(s authenticators.AuthDataSource) (string, error) {
	for _, e := range ce {
		if t, err := e.Extract(s); err == nil {
			return t, nil
		}
	}

	return "", ErrNoAuthDataPresent
}
