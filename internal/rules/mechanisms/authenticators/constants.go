package authenticators

const (
	AuthenticatorNoop                = "noop"
	AuthenticatorUnauthorized        = "unauthorized"
	AuthenticatorBasicAuth           = "basic_auth"
	AuthenticatorAnonymous           = "anonymous"
	AuthenticatorOAuth2Introspection = "oauth2_introspection"
	AuthenticatorJwt                 = "jwt"
	AuthenticatorGeneric             = "generic"
)
