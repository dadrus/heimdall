package config

import "github.com/dadrus/heimdall/authenticators/oauth2"

type ScopeStrategy string

type Asserter struct {
	ScopeStrategy     ScopeStrategy `json:"scope_strategy"`
	RequiredScopes    []string      `json:"required_scopes"`
	TargetAudiences   []string      `json:"target_audiences"`
	TrustedIssuers    []string      `json:"trusted_issuers"`
	AllowedAlgorithms []string      `json:"allowed_algorithms"`
}

func (Asserter) Assert(resp *oauth2.IntrospectionResponse) error {
	return nil
}
