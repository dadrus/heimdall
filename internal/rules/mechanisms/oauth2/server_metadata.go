package oauth2

import "github.com/dadrus/heimdall/internal/rules/endpoint"

type ServerMetadata struct {
	Issuer                string
	JWKSEndpoint          *endpoint.Endpoint
	IntrospectionEndpoint *endpoint.Endpoint
}
