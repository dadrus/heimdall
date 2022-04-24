package oauth2

import (
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ScopesMatcher struct {
	Matcher ScopeMatchingStrategy `mapstructure:"matching_strategy"`
	Scopes  Scopes                `mapstructure:"values"`
}

func (s ScopesMatcher) MatchScopes(scopes []string) error {
	for _, required := range s.Scopes {
		if !s.Matcher.Match(scopes, required) {
			return errorchain.NewWithMessagef(ErrClaimsNotValid, "required scope %s is missing", required)
		}
	}

	return nil
}
