package authenticators

import (
	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/rules/endpoint"
)

func newRenderFailingEndpoint(rawURL string, err error, opts ...endpoint.Option) *endpoint.Endpoint {
	ep := &endpoint.Endpoint{
		URL: renderFailingEndpointTemplate{
			value: rawURL,
			err:   err,
		},
	}

	for _, opt := range opts {
		opt(ep)
	}

	return ep
}

func newRenderFailingEndpointValue(rawURL string, err error, opts ...endpoint.Option) endpoint.Endpoint {
	return *newRenderFailingEndpoint(rawURL, err, opts...)
}

type renderFailingEndpointTemplate struct {
	value string
	err   error
}

func (t renderFailingEndpointTemplate) Render(map[string]any) (string, error) {
	if t.err != nil {
		return "", t.err
	}

	return "", assert.AnError
}

func (t renderFailingEndpointTemplate) Hash() []byte { return []byte(t.value) }

func (t renderFailingEndpointTemplate) String() string { return t.value }
