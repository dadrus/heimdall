package oauth2

import (
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
	return nil
}

func (s *mtlsPoPStrategy) Merge(other PopStrategy) PopStrategy {
	if other == nil {
		return s
	}

	return other
}
