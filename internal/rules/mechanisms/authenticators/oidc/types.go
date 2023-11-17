package oidc

type DiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	JWKSUrl               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}
