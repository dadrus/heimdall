package testsupport

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/endpoint"
)

func NewEndpoint(t *testing.T, rawURL string, opts ...endpoint.Option) *endpoint.Endpoint {
	t.Helper()

	ep, err := endpoint.New(rawURL, opts...)
	require.NoError(t, err)

	return ep
}

func EndpointValue(t *testing.T, rawURL string, opts ...endpoint.Option) endpoint.Endpoint {
	t.Helper()

	return *NewEndpoint(t, rawURL, opts...)
}
