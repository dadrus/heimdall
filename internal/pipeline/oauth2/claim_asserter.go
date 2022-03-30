package oauth2

type ClaimAsserter interface {
	AssertIssuer(issuer string) error
	AssertAudience(audience []string) error
	AssertScopes(scopes []string) error
	AssertValidity(nbf, exp int64) error
	IsAlgorithmAllowed(string) bool
}
