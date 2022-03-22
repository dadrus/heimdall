package extractors

import (
	"github.com/dadrus/heimdall/authenticators"
)

type CompositeExtractStrategy []AuthDataExtractStrategy

func (ce CompositeExtractStrategy) GetAuthData(s authenticators.AuthDataSource) (string, error) {
	for _, e := range ce {
		if t, err := e.GetAuthData(s); err == nil {
			return t, nil
		}
	}

	return "", ErrNoAuthDataPresent
}
