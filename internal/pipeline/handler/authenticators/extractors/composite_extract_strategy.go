package extractors

import (
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CompositeExtractStrategy []AuthDataExtractStrategy

func (ce CompositeExtractStrategy) GetAuthData(reqCtx handler.RequestContext) (string, error) {
	// nolint
	// preallocation not possible
	var errors []error

	for _, e := range ce {
		val, err := e.GetAuthData(reqCtx)
		if err == nil {
			return val, nil
		}

		errors = append(errors, err)
	}

	err := errorchain.New(errors[0])
	for i := 1; i < len(errors); i++ {
		err = err.CausedBy(errors[i])
	}

	return "", err
}
