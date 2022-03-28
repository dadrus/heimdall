package oauth2

import (
	"errors"

	"golang.org/x/exp/slices"
)

type ScopeStrategy string

type Assertions struct {
	ScopeStrategy     ScopeStrategy `json:"scope_strategy"`
	RequiredScopes    Scopes        `json:"required_scopes"`
	TargetAudiences   []string      `json:"target_audiences"`
	TrustedIssuers    []string      `json:"trusted_issuers"`
	AllowedAlgorithms []string      `json:"allowed_algorithms"`
}

func (a *Assertions) Validate() error {
	if len(a.TrustedIssuers) == 0 {
		return errors.New("missing trusted_issuers configuration")
	}
	return nil
}

func (a *Assertions) IsAlgorithmAllowed(alg string) bool {
	return slices.Contains(a.AllowedAlgorithms, alg)
}

func (a *Assertions) VerifyScopes(scopes Scopes) bool {
	return false
}
