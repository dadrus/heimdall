package handler

import (
	"errors"
	"fmt"
	"time"

	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
	"golang.org/x/exp/slices"
)

type ScopeStrategy string

type Assertions struct {
	ScopeStrategy     ScopeStrategy `yaml:"scope_strategy"`
	RequiredScopes    oauth2.Scopes `yaml:"required_scopes"`
	TargetAudiences   []string      `yaml:"target_audiences"`
	TrustedIssuers    []string      `yaml:"trusted_issuers"`
	AllowedAlgorithms []string      `yaml:"allowed_algorithms"`
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

func (a *Assertions) AssertScopes(scopes []string) error {
	return nil
}

func (a *Assertions) AssertValidity(nbf, exp int64) error {
	if exp == -1 {
		return errors.New("token does not expire")
	} else if exp < time.Now().Unix() {
		return errors.New("token is expired")
	}
	if nbf != -1 && nbf > time.Now().Unix() {
		return errors.New("token is not yet valid")
	}

	return nil
}

func (a *Assertions) AssertIssuer(iss string) error {
	if !slices.Contains(a.TrustedIssuers, iss) {
		return fmt.Errorf("issuer %s is not trusted", iss)
	}
	return nil
}

func (a *Assertions) AssertAudience(audience []string) error {
	if len(audience) == 0 && len(a.TargetAudiences) != 0 {
		return errors.New("audience expected, but not included within the token")
	}

	for _, aud := range audience {
		if !slices.Contains(a.TargetAudiences, aud) {
			return fmt.Errorf("token is not expected to have been issued for %s audience", aud)
		}
	}

	return nil
}
