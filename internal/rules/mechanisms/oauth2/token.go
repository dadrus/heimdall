package oauth2

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/dadrus/heimdall/internal/pipeline"
)

type TokenType string

const (
	TypeBearer TokenType = "Bearer"
	TypeDPoP   TokenType = "DPoP"
)

type Token struct {
	Raw  string
	Type TokenType

	Header    jose.Header
	RawClaims map[string]any

	// Claims is populated only after Verify() succeeds – values are signature-verified.
	Claims Claims

	jwt *jwt.JSONWebToken
}

func NewToken(tokenType TokenType, value string) (*Token, error) {
	if len(tokenType) == 0 {
		tokenType = TypeBearer
	}

	parsed, err := jwt.ParseSigned(value, SupportedAlgorithms())
	if err != nil {
		return nil, NewInvalidTokenError(tokenType, "invalid JWT format")
	}

	if len(parsed.Headers) == 0 {
		return nil, NewInvalidTokenError(tokenType, "missing JWT header")
	}

	var rawClaims map[string]any
	if err := parsed.UnsafeClaimsWithoutVerification(&rawClaims); err != nil {
		return nil, NewInvalidTokenError(tokenType, "failed to deserialize JWT payload")
	}

	return &Token{
		Raw:       value,
		Type:      tokenType,
		Header:    parsed.Headers[0],
		RawClaims: rawClaims,
		jwt:       parsed,
	}, nil
}

// NewIntrospectionToken creates a Token from an introspection response.
// The Claims are taken directly from the verified response; no JWT is parsed.
func NewIntrospectionToken(tokenType TokenType, raw string, claims Claims) *Token {
	return &Token{Raw: raw, Type: tokenType, Claims: claims}
}

func (t *Token) Verify(
	ctx pipeline.Context,
	expectation Expectation,
	key *jose.JSONWebKey,
) error {
	if len(t.Header.Algorithm) != 0 && key.Algorithm != t.Header.Algorithm {
		return NewInvalidTokenError(
			t.Type,
			"algorithm in the JWT header does not match the algorithm referenced in the key",
		)
	}

	if err := expectation.AssertAlgorithm(t); err != nil {
		return err
	}

	var claims Claims
	if err := t.jwt.Claims(key, &claims); err != nil {
		return NewInvalidTokenError(t.Type, "failed to verify JWT signature")
	}

	t.Claims = claims

	return t.Validate(ctx, expectation)
}

func (t *Token) Validate(ctx pipeline.Context, exp Expectation) error {
	if err := exp.AssertIssuer(t); err != nil {
		return err
	}

	if err := exp.AssertAudience(t); err != nil {
		return err
	}

	if err := exp.AssertValidity(t); err != nil {
		return err
	}

	if err := exp.AssertIssuanceTime(t); err != nil {
		return err
	}

	if err := exp.AssertProofOfPossession(ctx, t); err != nil {
		return err
	}

	return exp.AssertScopes(t)
}
