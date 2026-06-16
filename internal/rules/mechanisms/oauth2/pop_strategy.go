package oauth2

import (
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/pipeline"
)

type PoPType string

const (
	Undefined PoPType = ""
	DPoP      PoPType = "dpop"
	MTLS      PoPType = "mtls"
)

type PopStrategy interface {
	Assert(
		ctx pipeline.Context,
		token *Token,
		leeway time.Duration,
		allowedAlgorithms []jose.SignatureAlgorithm,
	) error

	Merge(other PopStrategy) PopStrategy
}
