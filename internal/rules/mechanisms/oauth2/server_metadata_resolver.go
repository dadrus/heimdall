package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/goccy/go-json"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ServerMetadataResolver interface {
	Get(ctx context.Context, args map[string]any) (ServerMetadata, error)
}

type ResolverAdapterFunc func(ctx context.Context, args map[string]any) (ServerMetadata, error)

func (f ResolverAdapterFunc) Get(ctx context.Context, args map[string]any) (ServerMetadata, error) {
	return f(ctx, args)
}

func NewServerMetadataResolver(ep *endpoint.Endpoint) ServerMetadataResolver {
	if ep.Headers == nil {
		ep.Headers = make(map[string]string)
	}

	if _, ok := ep.Headers["Accept"]; !ok {
		ep.Headers["Accept"] = "application/json"
	}

	if len(ep.Method) == 0 {
		ep.Method = http.MethodGet
	}

	if ep.HTTPCacheEnabled == nil {
		cacheEnabled := true

		ep.HTTPCacheEnabled = &cacheEnabled
	}

	return serverMetadataResolver{e: ep}
}

type serverMetadataResolver struct {
	e *endpoint.Endpoint
}

func (r serverMetadataResolver) Get(ctx context.Context, args map[string]any) (ServerMetadata, error) {
	req, err := r.e.CreateRequest(ctx, nil, endpoint.RenderFunc(func(value string) (string, error) {
		tpl, err := template.New(value)
		if err != nil {
			return "", errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create template").
				CausedBy(err)
		}

		return tpl.Render(args)
	}))
	if err != nil {
		return ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating oauth2 server metadata request").CausedBy(err)
	}

	resp, err := r.e.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrCommunicationTimeout,
				"request to oauth2 server metadata endpoint timed out").CausedBy(err)
		}

		return ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrCommunication,
			"request to oauth2 server metadata endpoint failed").CausedBy(err)
	}

	defer resp.Body.Close()

	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return ServerMetadata{}, errorchain.
			NewWithMessagef(heimdall.ErrCommunication, "unexpected response code: %v", resp.StatusCode)
	}

	return r.decodeResponse(resp)
}

func (r serverMetadataResolver) decodeResponse(resp *http.Response) (ServerMetadata, error) {
	type metadata struct {
		Issuer                   string `json:"issuer"`
		JWKSEndpointURL          string `json:"jwks_uri"`
		IntrospectionEndpointURL string `json:"introspection_endpoint"`
	}

	var spec metadata
	if err := json.NewDecoder(resp.Body).Decode(&spec); err != nil {
		return ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to unmarshal received oauth2 server metadata document").CausedBy(err)
	}

	if strings.Contains(spec.JWKSEndpointURL, "{{") &&
		strings.Contains(spec.JWKSEndpointURL, "}}") {
		return ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"received jwks_uri contains a template, which is not allowed")
	}

	if strings.Contains(spec.IntrospectionEndpointURL, "{{") &&
		strings.Contains(spec.IntrospectionEndpointURL, "}}") {
		return ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"received introspection_endpoint contains a template, which is not allowed")
	}

	var (
		jwksEP          *endpoint.Endpoint
		introspectionEP *endpoint.Endpoint
	)

	if len(spec.JWKSEndpointURL) != 0 {
		jwksEP = &endpoint.Endpoint{
			URL:     spec.JWKSEndpointURL,
			Method:  http.MethodGet,
			Headers: map[string]string{"Accept": "application/json"},
		}
	}

	if len(spec.IntrospectionEndpointURL) != 0 {
		introspectionEP = &endpoint.Endpoint{
			URL:    spec.IntrospectionEndpointURL,
			Method: http.MethodPost,
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"Accept":       "application/json",
			},
		}
	}

	return ServerMetadata{
		Issuer:                spec.Issuer,
		JWKSEndpoint:          jwksEP,
		IntrospectionEndpoint: introspectionEP,
	}, nil
}
