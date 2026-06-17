package oauth2

import (
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/pipeline"
)

type opportunisticPoPStrategy struct{}

func (s opportunisticPoPStrategy) Assert(
	ctx pipeline.Context,
	token *Token,
	leeway time.Duration,
	allowedAlgorithms []jose.SignatureAlgorithm,
) error {
	cnf := token.Claims.Confirmation
	if cnf == nil {
		return nil
	}

	if len(cnf.JWKThumbprint) != 0 {
		return (&demonstratingPoPStrategy{}).Assert(ctx, token, leeway, allowedAlgorithms)
	}

	if len(cnf.CertificateThumbprintSHA256) != 0 {
		return (&mtlsPoPStrategy{}).Assert(ctx, token, leeway, allowedAlgorithms)
	}

	return nil
}

func (s opportunisticPoPStrategy) Merge(other PoPStrategy) PoPStrategy {
	if other == nil {
		return s
	}

	return other
}
