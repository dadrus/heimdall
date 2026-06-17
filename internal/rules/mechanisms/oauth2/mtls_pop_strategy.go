package oauth2

import (
	"errors"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/pipeline"
)

type mtlsPoPStrategy struct{}

func (*mtlsPoPStrategy) Assert(
	_ pipeline.Context,
	_ *Token,
	_ time.Duration,
	_ []jose.SignatureAlgorithm,
) error {
	return errors.New("mtls pop strategy not supported")
}

func (s *mtlsPoPStrategy) Merge(other PoPStrategy) PoPStrategy {
	if other == nil {
		return s
	}

	return other
}
