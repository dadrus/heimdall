package oauth2

import (
	"errors"
	"time"

	"golang.org/x/exp/slices"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrConfiguration = errors.New("malformed configuration")

// ScopeStrategy is a strategy for matching scopes.
type ScopeStrategy func(haystack []string, needle string) bool

func (s *ScopeStrategy) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v string
	if err := unmarshal(&v); err != nil {
		return err
	}

	switch v {
	case "wildcard":
		*s = WildcardScopeStrategy
	case "hierarchic":
		*s = HierarchicScopeStrategy
	default:
		*s = ExactScopeStrategy
	}

	return nil
}

type Duration time.Duration

func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v string
	if err := unmarshal(&v); err != nil {
		return err
	}

	pd, err := time.ParseDuration(v)
	*d = Duration(pd)

	return err
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

type Expectation struct {
	ScopeStrategy     ScopeStrategy `yaml:"scope_strategy"`
	RequiredScopes    Scopes        `yaml:"required_scopes"`
	TargetAudiences   []string      `yaml:"target_audiences"`
	TrustedIssuers    []string      `yaml:"trusted_issuers"`
	AllowedAlgorithms []string      `yaml:"allowed_algorithms"`
	ValidityLeeway    Duration      `yaml:"validity_leeway"`
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
