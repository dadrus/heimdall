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

func (e *Expectation) Merge(other *Expectation) Expectation {
	if e == nil {
		return *other
	}

	e.TrustedIssuers = x.IfThenElse(len(e.TrustedIssuers) != 0, e.TrustedIssuers, other.TrustedIssuers)
	e.ScopesMatcher = x.IfThenElse(e.ScopesMatcher != nil, e.ScopesMatcher, other.ScopesMatcher)
	e.TargetAudiences = x.IfThenElse(len(e.TargetAudiences) != 0, e.TargetAudiences, other.TargetAudiences)
	e.AllowedAlgorithms = x.IfThenElse(len(e.AllowedAlgorithms) != 0, e.AllowedAlgorithms, other.AllowedAlgorithms)
	e.ValidityLeeway = x.IfThenElse(e.ValidityLeeway != 0, e.ValidityLeeway, other.ValidityLeeway)

	return *e
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
	leeway := int64(x.IfThenElse(e.ValidityLeeway != 0, e.ValidityLeeway, defaultLeeway).Seconds())
	now := time.Now().Unix()
	nbf := notBefore.Unix()
	exp := notAfter.Unix()

	if nbf > 0 && now+leeway < nbf {
		return errorchain.NewWithMessage(ErrAssertion, "not yet valid")
	}

	if exp > 0 && now-leeway >= exp {
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
		return err
	}

	return nil
}
