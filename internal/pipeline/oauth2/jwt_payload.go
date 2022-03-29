package oauth2

import (
	"errors"
	"strings"
)

type ClaimAsserter interface {
	AssertIssuer(issuer string) error
	AssertAudience(audience []string) error
	AssertScopes(scopes []string) error
	AssertValidity(nbf, exp int64) error
	IsAlgorithmAllowed(string) bool
}

func getClaim[T any](claims map[string]interface{}, name string, defVal T) T {
	if c, ok := claims[name]; ok {
		if v, ok := c.(T); !ok {
			return defVal
		} else {
			return v
		}
	}

	return defVal
}

type JwtPayload map[string]interface{}

func (jp JwtPayload) checkIssuer(asserter ClaimAsserter) error {
	if issuer, ok := jp["iss"]; !ok {
		return errors.New("token does not contain iss claim")
	} else {
		return asserter.AssertIssuer(issuer.(string))
	}
}

func (jp JwtPayload) checkAudience(asserter ClaimAsserter) error {
	var audience []string
	aud := getClaim(jp, "aud", "")
	if len(aud) == 0 {
		audience = getClaim(jp, "aud", []string{})
	} else {
		audience = strings.Split(aud, " ")
	}

	return asserter.AssertAudience(audience)
}

func (jp JwtPayload) checkTokenId() error {
	if _, ok := jp["jti"]; !ok {
		return errors.New("token does not contain jti claim")
	}
	return nil
}

func (jp JwtPayload) checkScopes(asserter ClaimAsserter) error {
	var scopes []string
	scope := getClaim(jp, "scope", "")
	if len(scope) == 0 {
		scopes = getClaim(jp, "scope", []string{})
	} else {
		scopes = strings.Split(scope, " ")
	}

	if len(scopes) == 0 {
		scp := getClaim(jp, "scp", "")
		if len(scp) == 0 {
			scopes = getClaim(jp, "scp", []string{})
		} else {
			scopes = strings.Split(scp, " ")
		}
	}

	return asserter.AssertScopes(scopes)
}

func (jp JwtPayload) checkTimeValidity(asserter ClaimAsserter) error {
	nbf := getClaim(jp, "nbf", int64(-1))
	exp := getClaim(jp, "exp", int64(-1))

	return asserter.AssertValidity(nbf, exp)
}

func (jp JwtPayload) Verify(asserter ClaimAsserter) error {
	if err := jp.checkIssuer(asserter); err != nil {
		return err
	}

	if err := jp.checkAudience(asserter); err != nil {
		return err
	}

	if err := jp.checkScopes(asserter); err != nil {
		return err
	}

	if err := jp.checkTokenId(); err != nil {
		return err
	}

	if err := jp.checkTimeValidity(asserter); err != nil {
		return err
	}

	return nil
}
