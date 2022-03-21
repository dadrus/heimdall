package extractors

import (
	"errors"
)

type TokenExtractor interface {
	Extract(s AuthDataSource) (string, error)
}

type CompositeExtractor []TokenExtractor

func (ce CompositeExtractor) Extract(s AuthDataSource) (string, error) {
	for _, e := range ce {
		if t, err := e.Extract(s); err == nil {
			return t, nil
		}
	}

	return "", errors.New("no auth data present")
}

func NewCompositeExtractor(extractor ...TokenExtractor) TokenExtractor {
	var chain CompositeExtractor

	for _, e := range extractor {
		chain = append(chain, e)
	}

	return chain
}
