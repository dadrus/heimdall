package oauth2

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
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
	checkScope := x.IfThenElse(exp.ScopeStrategy != nil, exp.ScopeStrategy, ExactScopeStrategy)

	for _, requiredScope := range exp.RequiredScopes {
		if !checkScope(receivedScopes, requiredScope) {
			return errorchain.NewWithMessagef(ErrClaimsNotValid, "required scope %s is missing", requiredScope)
		}
	}

	return nil
}

func (c Claims) validateTimeValidity(exp Expectation) error {
	var leeway time.Duration
	if exp.ValidityLeeway != 0 {
		leeway = exp.ValidityLeeway.Duration()
	} else {
		leeway = defaultLeeway * time.Second
	}

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

// NumericDate represents date and time as the number of seconds since the
// epoch, ignoring leap seconds. Non-integer values can be represented
// in the serialized format, but we round to the nearest second.
// See RFC7519 Section 2: https://tools.ietf.org/html/rfc7519#section-2
type NumericDate int64

// UnmarshalJSON reads a date from its JSON representation.
func (n *NumericDate) UnmarshalJSON(b []byte) error {
	const floatPrecision = 64

	f, err := strconv.ParseFloat(string(b), floatPrecision)
	if err != nil {
		return errorchain.NewWithMessage(ErrConfiguration, "failed to parse date").CausedBy(err)
	}

	*n = NumericDate(f)

	return nil
}

// Time returns time.Time representation of NumericDate.
func (n *NumericDate) Time() time.Time {
	if n == nil {
		return time.Time{}
	}

	return time.Unix(int64(*n), 0)
}

// Audience represents the recipients that the token is intended for.
type Audience []string

// UnmarshalJSON reads an audience from its JSON representation.
func (s *Audience) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return errorchain.NewWithMessage(ErrConfiguration, "failed to unmarshal audience").CausedBy(err)
	}

	switch value := v.(type) {
	case string:
		*s = strings.Split(value, " ")
	case []interface{}:
		array := make([]string, len(value))

		for idx, val := range value {
			s, ok := val.(string)
			if !ok {
				return errorchain.NewWithMessage(ErrConfiguration, "failed to parse audience array")
			}

			array[idx] = s
		}

		*s = array
	default:
		return errorchain.NewWithMessage(ErrConfiguration, "unexpected content for audience")
	}

	return nil
}

// Scopes represents the scopes that the token is granted.
type Scopes []string

// UnmarshalJSON reads scopes from its JSON representation.
func (s *Scopes) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return errorchain.NewWithMessage(ErrConfiguration, "failed to unmarshal scopes").CausedBy(err)
	}

	switch value := v.(type) {
	case string:
		*s = strings.Split(value, " ")
	case []interface{}:
		array := make([]string, len(value))

		for idx, val := range value {
			s, ok := val.(string)
			if !ok {
				return errorchain.NewWithMessage(ErrConfiguration, "failed to parse scopes array")
			}

			array[idx] = s
		}

		*s = array
	default:
		return errorchain.NewWithMessage(ErrConfiguration, "unexpected content for scopes")
	}

	return nil
}
