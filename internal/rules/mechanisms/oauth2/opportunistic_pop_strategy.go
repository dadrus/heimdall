package oauth2

import (
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/pipeline"
)

type opportunisticPoPStrategy struct{}

func (s opportunisticPoPStrategy) Assert(
	ctx pipeline.Context,
	cnf *Confirmation,
	rawToken string,
	leeway time.Duration,
	allowedAlgorithms []jose.SignatureAlgorithm,
) error {
	if cnf == nil {
		return nil
	}

	if len(cnf.JWKThumbprint) != 0 {
		dpop := &demonstratingPoPStrategy{}

		return dpop.Assert(ctx, cnf, rawToken, leeway, allowedAlgorithms)
	}

	if len(cnf.CertificateThumbprintSHA256) != 0 {
		mpop := &mtlsPoPStrategy{}

		return mpop.Assert(ctx, cnf, rawToken, leeway, allowedAlgorithms)
	}

	return nil
}

func (s opportunisticPoPStrategy) Merge(other PopStrategy) PopStrategy {
	if other == nil {
		return s
	}

	return other
}
