package oauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dadrus/heimdall/internal/x"
	"golang.org/x/exp/slices"
)

var defaultLeeway = time.Duration(10)

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

func (c Claims) Validate(a Expectation) error {
	if !slices.Contains(a.TrustedIssuers, c.Issuer) {
		return fmt.Errorf("issuer is not trusted: %s", c.Issuer)
	}

	for _, aud := range a.TargetAudiences {
		if !slices.Contains(c.Audience, aud) {
			return fmt.Errorf("required audience %s is not asserted", c.Issuer)
		}
	}

	var leeway time.Duration
	if a.ValidityLeeway != 0 {
		leeway = a.ValidityLeeway.Duration()
	} else {
		leeway = defaultLeeway * time.Second
	}

	now := time.Now()
	if c.NotBefore != nil && now.Add(leeway).Before(c.NotBefore.Time()) {
		return errors.New("claims not valid yet")
	}

	if c.Expiry != nil && now.Add(-leeway).After(c.Expiry.Time()) {
		return errors.New("claims expired")
	}

	// IssuedAt is optional but cannot be in the future. This is not required by the RFC, but
	// if by misconfiguration it has been set to future, we don't trust it.
	if c.IssuedAt != nil && now.Add(leeway).Before(c.IssuedAt.Time()) {
		return errors.New("claims issued in the future")
	}

	receivedScopes := x.IfThenElse(len(c.Scp) != 0, c.Scp, c.Scope)
	checkScope := x.IfThenElse(a.ScopeStrategy != nil, a.ScopeStrategy, ExactScopeStrategy)

	for _, requiredScope := range a.RequiredScopes {
		if !checkScope(receivedScopes, requiredScope) {
			return fmt.Errorf("required scope %s is missing", requiredScope)
		}
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
	s := string(b)

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return errors.New("failed to parse date")
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
		return err
	}

	switch v := v.(type) {
	case string:
		*s = strings.Split(v, " ")
	case []interface{}:
		array := make([]string, len(v))
		for i, e := range v {
			s, ok := e.(string)
			if !ok {
				return errors.New("failed to unmarshal audience")
			}
			array[i] = s
		}
		*s = array
	default:
		return errors.New("failed to unmarshal audience")
	}

	return nil
}

// Scopes represents the scopes that the token is granted.
type Scopes []string

// UnmarshalJSON reads scopes from its JSON representation.
func (s *Scopes) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}

	switch v := v.(type) {
	case string:
		*s = strings.Split(v, " ")
	case []interface{}:
		array := make([]string, len(v))
		for i, e := range v {
			s, ok := e.(string)
			if !ok {
				return errors.New("failed to unmarshal scopes")
			}
			array[i] = s
		}
		*s = array
	default:
		return errors.New("failed to unmarshal scopes")
	}

	return nil
}
