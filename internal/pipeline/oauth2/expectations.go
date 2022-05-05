package oauth2

import (
	"errors"
	"time"

	"golang.org/x/exp/slices"

	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const defaultLeeway = 10 * time.Second

var ErrAssertion = errors.New("assertion error")

type Expectation struct {
	ScopesMatcher     ScopesMatcher `mapstructure:"scopes"`
	TargetAudiences   []string      `mapstructure:"audience"`
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

func (e *Expectation) AssertAlgorithm(alg string) error {
	if !slices.Contains(e.AllowedAlgorithms, alg) {
		return errorchain.NewWithMessagef(ErrAssertion, "algorithm %s is not allowed", alg)
	}

	return nil
}

func (e *Expectation) AssertIssuer(issuer string) error {
	if !slices.Contains(e.TrustedIssuers, issuer) {
		return errorchain.NewWithMessagef(ErrAssertion, "issuer %s is not trusted", issuer)
	}

	return nil
}

func (e *Expectation) AssertAudience(audience []string) error {
	for _, aud := range e.TargetAudiences {
		if !slices.Contains(audience, aud) {
			return errorchain.NewWithMessagef(ErrAssertion, "audience %s is not expected", aud)
		}
	}

	return nil
}

func (e *Expectation) AssertValidity(notBefore, notAfter time.Time) error {
	leeway := x.IfThenElse(e.ValidityLeeway != 0, e.ValidityLeeway, defaultLeeway)

	now := time.Now()
	if !notBefore.Equal(time.Time{}) && now.Add(leeway).Before(notBefore) {
		return errorchain.NewWithMessage(ErrAssertion, "not yet valid")
	}

	if !notAfter.Equal(time.Time{}) && now.Add(-leeway).After(notAfter) {
		return errorchain.NewWithMessage(ErrAssertion, "expired")
	}

	return nil
}

func (e *Expectation) AssertIssuanceTime(issuedAt time.Time) error {
	leeway := x.IfThenElse(e.ValidityLeeway != 0, e.ValidityLeeway, defaultLeeway)

	// IssuedAt is optional but cannot be in the future. This is not required by the RFC, but
	// if by misconfiguration it has been set to future, we don't trust it.
	if !issuedAt.Equal(time.Time{}) && time.Now().Add(leeway).Before(issuedAt) {
		return errorchain.NewWithMessage(ErrAssertion, "issued in the future")
	}

	return nil
}

func (e *Expectation) AssertScopes(scopes []string) error {
	if err := e.ScopesMatcher.Match(scopes); err != nil {
		return errorchain.NewWithMessage(ErrAssertion, "scopes not valid").CausedBy(err)
	}

	return nil
}
