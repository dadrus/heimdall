package oauth2

import (
	"github.com/dadrus/heimdall/internal/x"
)

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
	if err := exp.AssertIssuer(c.Issuer); err != nil {
		return err
	}

	if err := exp.AssertAudience(c.Audience); err != nil {
		return err
	}

	if err := exp.AssertValidity(c.NotBefore.Time(), c.Expiry.Time()); err != nil {
		return err
	}

	if err := exp.AssertIssuanceTime(c.IssuedAt.Time()); err != nil {
		return err
	}

	if err := exp.AssertScopes(x.IfThenElse(len(c.Scp) != 0, c.Scp, c.Scope)); err != nil {
		return err
	}

	return nil
}
