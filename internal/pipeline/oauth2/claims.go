package oauth2

import (
	"errors"
	"time"

	"golang.org/x/exp/slices"

	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const defaultLeeway = 10

var ErrClaimsNotValid = errors.New("claims not valid")

// Claims represents public claim values (as specified in RFC 7519).
type Claims struct {
	Issuer    string       `json:"iss,omitempty"`
	Subject   string       `json:"sub,omitempty"`
	Audience  Audience     `json:"aud,omitempty"`
	Scp       Scopes       `json:"scp,omitempty"`
	Scope     Scopes       `json:"scope,omitempty"`
	Expiry    *NumericDate `json:"exp,omitempty"`
	NotBefore *NumericDate `json:"nbf,omitempty"`
	IssuedAt  *NumericDate `json:"iat,omitempty"`
	ID        string       `json:"jti,omitempty"`
}

func (c Claims) Validate(exp Expectation) error {
	if !slices.Contains(exp.TrustedIssuers, c.Issuer) {
		return errorchain.NewWithMessagef(ErrClaimsNotValid, "issuer \"%s\" is not trusted", c.Issuer)
	}

	for _, aud := range exp.TargetAudiences {
		if !slices.Contains(c.Audience, aud) {
			return errorchain.NewWithMessagef(ErrClaimsNotValid, "required audience \"%s\" is not asserted", aud)
		}
	}

	if err := c.validateTimeValidity(exp); err != nil {
		return err
	}

	if err := c.validateScopes(exp); err != nil {
		return err
	}

	return nil
}

func (c Claims) validateScopes(exp Expectation) error {
	receivedScopes := x.IfThenElse(len(c.Scp) != 0, c.Scp, c.Scope)

	return exp.ScopesMatcher.Match(receivedScopes)
}

func (c Claims) validateTimeValidity(exp Expectation) error {
	leeway := x.IfThenElse(exp.ValidityLeeway != 0, exp.ValidityLeeway, defaultLeeway*time.Second)

	now := time.Now()
	if c.NotBefore != nil && now.Add(leeway).Before(c.NotBefore.Time()) {
		return errorchain.NewWithMessage(ErrClaimsNotValid, "not yet valid (time)")
	}

	if c.Expiry != nil && now.Add(-leeway).After(c.Expiry.Time()) {
		return errorchain.NewWithMessage(ErrClaimsNotValid, "expired (time)")
	}

	// IssuedAt is optional but cannot be in the future. This is not required by the RFC, but
	// if by misconfiguration it has been set to future, we don't trust it.
	if c.IssuedAt != nil && now.Add(leeway).Before(c.IssuedAt.Time()) {
		return errorchain.NewWithMessage(ErrClaimsNotValid, "issued in the future (time)")
	}

	return nil
}
