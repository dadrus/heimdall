package oauth2

import (
	"errors"
	"time"

	"golang.org/x/exp/slices"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrConfiguration = errors.New("malformed configuration")

type Expectation struct {
	ScopesMatcher     ScopesMatcher `mapstructure:"scopes"`
	TargetAudiences   []string      `mapstructure:"audiences"`
	TrustedIssuers    []string      `mapstructure:"issuers"`
	AllowedAlgorithms []string      `mapstructure:"allowed_algorithms"`
	ValidityLeeway    time.Duration `mapstructure:"validity_leeway"`
}

func (e *Expectation) Validate() error {
	if len(e.TrustedIssuers) == 0 {
		return errorchain.NewWithMessage(ErrConfiguration, "missing trusted_issuers configuration")
	}

	return nil
}

func (e *Expectation) IsAlgorithmAllowed(alg string) bool {
	return slices.Contains(e.AllowedAlgorithms, alg)
}
