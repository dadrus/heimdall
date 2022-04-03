package extractors

import (
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CompositeExtractStrategy []AuthDataExtractStrategy

func (ce CompositeExtractStrategy) GetAuthData(s handler.RequestContext) (string, error) {
	var errors []error

	for _, e := range ce {
		if val, err := e.GetAuthData(s); err == nil {
			return val, nil
		} else {
			errors = append(errors, err)
		}
	}

	err := errorchain.New(errors[0])
	for i := 1; i < len(errors); i++ {
		err = err.CausedBy(errors[i])
	}

	return "", err
}
