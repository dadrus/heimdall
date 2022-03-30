package oauth2

import (
	"errors"
	"strings"
)

type IntrospectionResponse map[string]interface{}

// Active    bool   `json:"active"`
// Scopes    Scopes `json:"scope"`
// ClientId  string `json:"client_id"`
// Username  string `json:"username"`
// TokenType string `json:"token_type"`

func (ir IntrospectionResponse) checkScopes(asserter ClaimAsserter) error {
	var scopes []string
	scope := getClaim(ir, "scope", "")
	if len(scope) == 0 {
		scopes = getClaim(ir, "scope", []string{})
	} else {
		scopes = strings.Split(scope, " ")
	}

	if len(scopes) == 0 {
		scp := getClaim(ir, "scp", "")
		if len(scp) == 0 {
			scopes = getClaim(ir, "scp", []string{})
		} else {
			scopes = strings.Split(scp, " ")
		}
	}

	return asserter.AssertScopes(scopes)
}

func (ir IntrospectionResponse) Verify(asserter ClaimAsserter) error {
	active := getClaim(ir, "active", false)
	if !active {
		return errors.New("token is not active")
	}

	if err := ir.checkScopes(asserter); err != nil {
		return err
	}

	return nil
}
