package config

import (
	"golang.org/x/exp/slices"
)

type ScopeStrategy string

type Scopes []string

type Assertions struct {
	ScopeStrategy     ScopeStrategy `json:"scope_strategy"`
	RequiredScopes    Scopes        `json:"required_scopes"`
	TargetAudiences   []string      `json:"target_audiences"`
	TrustedIssuers    []string      `json:"trusted_issuers"`
	AllowedAlgorithms []string      `json:"allowed_algorithms"`
}

func (a *Assertions) IsAlgorithmAllowed(alg string) bool {
	return slices.Contains(a.AllowedAlgorithms, alg)
}

func (a *Assertions) VerifyScopes(scopes Scopes) bool {
	return false
}
