package oauth2

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/dadrus/heimdall/internal/pipeline"
)

type TokenScheme string

const (
	SchemeBearer TokenScheme = "Bearer"
	SchemeDPoP   TokenScheme = "DPoP"
)

type Token struct {
	Raw    string
	Scheme TokenScheme

	Header    jose.Header
	RawClaims map[string]any

	// Claims is populated only after Verify() succeeds – values are signature-verified.
	Claims Claims

	jwt *jwt.JSONWebToken
}

func NewToken(raw, scheme string) (*Token, error) {
	tokenScheme := TokenScheme(scheme)
	if len(tokenScheme) == 0 {
		tokenScheme = SchemeBearer
	}

	parsed, err := jwt.ParseSigned(raw, SupportedAlgorithms())
	if err != nil {
		return nil, NewInvalidTokenError(tokenScheme, "invalid JWT format")
	}

	if len(parsed.Headers) == 0 {
		return nil, NewInvalidTokenError(tokenScheme, "missing JWT header")
	}

	var rawClaims map[string]any
	if err := parsed.UnsafeClaimsWithoutVerification(&rawClaims); err != nil {
		return nil, NewInvalidTokenError(tokenScheme, "failed to deserialize JWT payload")
	}

	return &Token{
		Raw:       raw,
		Scheme:    tokenScheme,
		Header:    parsed.Headers[0],
		RawClaims: rawClaims,
		jwt:       parsed,
	}, nil
}

// NewIntrospectionToken creates a Token from an introspection response.
// The Claims are taken directly from the verified response; no JWT is parsed.
func NewIntrospectionToken(scheme TokenScheme, raw string, claims Claims) *Token {
	return &Token{Raw: raw, Scheme: scheme, Claims: claims}
}

func (t *Token) Verify(
	ctx pipeline.Context,
	key *jose.JSONWebKey,
	expectation Expectation,
) error {
	if len(t.Header.Algorithm) != 0 && key.Algorithm != t.Header.Algorithm {
		return NewInvalidTokenError(
			t.Scheme,
			"algorithm in the JWT header does not match the algorithm referenced in the key",
		)
	}

	if err := expectation.AssertAlgorithm(t, jose.SignatureAlgorithm(key.Algorithm)); err != nil {
		return err
	}

	var claims Claims
	if err := t.jwt.Claims(key, &claims); err != nil {
		return NewInvalidTokenError(t.Scheme, "failed to verify JWT signature")
	}

	t.Claims = claims

	return claims.Validate(ctx, t, expectation)
}
