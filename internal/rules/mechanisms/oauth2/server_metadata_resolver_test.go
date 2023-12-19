package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/x"
)

func TestNewServerMetadataResolver(t *testing.T) {
	t.Parallel()

	falseValue := false
	trueValue := true

	for _, tc := range []struct {
		uc  string
		ep  endpoint.Endpoint
		exp endpoint.Endpoint
	}{
		{
			uc: "only URL is set",
			ep: endpoint.Endpoint{URL: "https://foo.bar"},
			exp: endpoint.Endpoint{
				URL:              "https://foo.bar",
				Method:           http.MethodGet,
				Headers:          map[string]string{"Accept": "application/json"},
				HTTPCacheEnabled: &trueValue,
			},
		},
		{
			uc: "URL is set and http cache is disabled",
			ep: endpoint.Endpoint{URL: "https://foo.bar", HTTPCacheEnabled: &falseValue},
			exp: endpoint.Endpoint{
				URL:              "https://foo.bar",
				Method:           http.MethodGet,
				Headers:          map[string]string{"Accept": "application/json"},
				HTTPCacheEnabled: &falseValue,
			},
		},
		{
			uc: "URL and method are set",
			ep: endpoint.Endpoint{URL: "https://foo.bar", Method: http.MethodPost},
			exp: endpoint.Endpoint{
				URL:              "https://foo.bar",
				Method:           http.MethodPost,
				Headers:          map[string]string{"Accept": "application/json"},
				HTTPCacheEnabled: &trueValue,
			},
		},
		{
			uc: "URL and some headers are set",
			ep: endpoint.Endpoint{URL: "https://foo.bar", Headers: map[string]string{"X-Foo": "bar"}},
			exp: endpoint.Endpoint{
				URL:    "https://foo.bar",
				Method: http.MethodGet,
				Headers: map[string]string{
					"Accept": "application/json",
					"X-Foo":  "bar",
				},
				HTTPCacheEnabled: &trueValue,
			},
		},
		{
			uc: "URL and accept-type header are set",
			ep: endpoint.Endpoint{URL: "https://foo.bar", Headers: map[string]string{"Accept": "text/html"}},
			exp: endpoint.Endpoint{
				URL:              "https://foo.bar",
				Method:           http.MethodGet,
				Headers:          map[string]string{"Accept": "text/html"},
				HTTPCacheEnabled: &trueValue,
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			ep := tc.ep
			resolver := NewServerMetadataResolver(&ep)

			mr := resolver.(serverMetadataResolver) // nolint: forcetypeassert

			assert.Equal(t, tc.exp, *mr.e)
		})
	}
}

func TestServerMetadataResolverGet(t *testing.T) {
	t.Parallel()

	type metadata struct {
		Issuer                             string   `json:"issuer"`
		JWKSEndpointURL                    string   `json:"jwks_uri"`
		IntrospectionEndpointURL           string   `json:"introspection_endpoint"`
		TokenEndpointAuthSigningAlgorithms []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	}

	var (
		endpointCalled bool
		checkRequest   func(req *http.Request)
		buildResponse  func(rw http.ResponseWriter)
	)

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		endpointCalled = true

		checkRequest(req)
		buildResponse(rw)
	}))

	defer srv.Close()

	for _, tc := range []struct {
		uc             string
		buildURL       func(t *testing.T, baseURL string) string
		args           map[string]any
		checkRequest   func(t *testing.T, req *http.Request)
		createResponse func(t *testing.T, rw http.ResponseWriter)
		assert         func(t *testing.T, endpointCalled bool, err error, sm ServerMetadata)
	}{
		{
			uc: "invalid template in path",
			buildURL: func(t *testing.T, baseURL string) string {
				t.Helper()

				return fmt.Sprintf("%s/{{ Foo }}", srv.URL)
			},
			assert: func(t *testing.T, endpointCalled bool, err error, sm ServerMetadata) {
				t.Helper()

				require.False(t, endpointCalled)
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "create template")
			},
		},
		{
			uc: "failed rendering template in path",
			buildURL: func(t *testing.T, baseURL string) string {
				t.Helper()

				return fmt.Sprintf("%s/{{ .Foo }", srv.URL)
			},
			assert: func(t *testing.T, endpointCalled bool, err error, sm ServerMetadata) {
				t.Helper()

				require.False(t, endpointCalled)
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "creating oauth2 server metadata request")
			},
		},
		{
			uc: "failed communicating with server",
			buildURL: func(t *testing.T, baseURL string) string {
				t.Helper()

				return "http://heimdall.test.local/foo"
			},
			assert: func(t *testing.T, endpointCalled bool, err error, sm ServerMetadata) {
				t.Helper()

				require.False(t, endpointCalled)
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
			},
		},
		{
			uc: "server responses with an error",
			buildURL: func(t *testing.T, baseURL string) string {
				t.Helper()

				return baseURL
			},
			createResponse: func(t *testing.T, rw http.ResponseWriter) {
				t.Helper()

				rw.WriteHeader(http.StatusBadRequest)
			},
			assert: func(t *testing.T, endpointCalled bool, err error, sm ServerMetadata) {
				t.Helper()

				require.True(t, endpointCalled)
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				require.ErrorContains(t, err, "unexpected response code")
			},
		},
		{
			uc: "server does not respond with a JSON document",
			buildURL: func(t *testing.T, baseURL string) string {
				t.Helper()

				return baseURL
			},
			createResponse: func(t *testing.T, rw http.ResponseWriter) {
				t.Helper()

				rw.Write([]byte("bad response"))
			},
			assert: func(t *testing.T, endpointCalled bool, err error, sm ServerMetadata) {
				t.Helper()

				require.True(t, endpointCalled)
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed to unmarshal")
			},
		},
		{
			uc: "server's response contains jwks_uri with template",
			buildURL: func(t *testing.T, baseURL string) string {
				t.Helper()

				return baseURL
			},
			checkRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "/", req.URL.Path)
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, "application/json", req.Header.Get("Accept"))
			},
			createResponse: func(t *testing.T, rw http.ResponseWriter) {
				t.Helper()

				rw.Header().Set("Content-Type", "application/json")

				err := json.NewEncoder(rw).Encode(metadata{
					Issuer:                             "heimdall.test",
					JWKSEndpointURL:                    "https://foo.bar/jwks/{{ .Foo }}",
					IntrospectionEndpointURL:           "https://foo.bar/introspection",
					TokenEndpointAuthSigningAlgorithms: []string{"RS256", "PS384"},
				})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, endpointCalled bool, err error, sm ServerMetadata) {
				t.Helper()

				require.True(t, endpointCalled)
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "jwks_uri contains a template")
			},
		},
		{
			uc: "server's response contains introspection_endpoint with template",
			buildURL: func(t *testing.T, baseURL string) string {
				t.Helper()

				return baseURL
			},
			checkRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "/", req.URL.Path)
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, "application/json", req.Header.Get("Accept"))
			},
			createResponse: func(t *testing.T, rw http.ResponseWriter) {
				t.Helper()

				rw.Header().Set("Content-Type", "application/json")

				err := json.NewEncoder(rw).Encode(metadata{
					Issuer:                             "heimdall.test",
					JWKSEndpointURL:                    "https://foo.bar/jwks",
					IntrospectionEndpointURL:           "https://foo.bar/{{ .Foo }}/introspection",
					TokenEndpointAuthSigningAlgorithms: []string{"RS256", "PS384"},
				})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, endpointCalled bool, err error, sm ServerMetadata) {
				t.Helper()

				require.True(t, endpointCalled)
				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "introspection_endpoint contains a template")
			},
		},
		{
			uc:   "valid server response for templated URL",
			args: map[string]any{"Foo": "bar"},
			buildURL: func(t *testing.T, baseURL string) string {
				t.Helper()

				return fmt.Sprintf("%s/{{ .Foo }}", baseURL)
			},
			checkRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "/bar", req.URL.Path)
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, "application/json", req.Header.Get("Accept"))
			},
			createResponse: func(t *testing.T, rw http.ResponseWriter) {
				t.Helper()

				rw.Header().Set("Content-Type", "application/json")

				err := json.NewEncoder(rw).Encode(metadata{
					Issuer:                             "heimdall.test",
					JWKSEndpointURL:                    "https://foo.bar/jwks",
					IntrospectionEndpointURL:           "https://foo.bar/introspection",
					TokenEndpointAuthSigningAlgorithms: []string{"RS256", "PS384"},
				})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, endpointCalled bool, err error, sm ServerMetadata) {
				t.Helper()

				require.True(t, endpointCalled)
				require.NoError(t, err)

				assert.Equal(t, "heimdall.test", sm.Issuer)

				exp := endpoint.Endpoint{
					URL:     "https://foo.bar/jwks",
					Method:  http.MethodGet,
					Headers: map[string]string{"Accept": "application/json"},
				}
				assert.Equal(t, exp, *sm.JWKSEndpoint)

				exp = endpoint.Endpoint{
					URL:    "https://foo.bar/introspection",
					Method: http.MethodPost,
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
						"Accept":       "application/json",
					},
				}
				assert.Equal(t, exp, *sm.IntrospectionEndpoint)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			endpointCalled = false

			testRequest := x.IfThenElse(
				tc.checkRequest != nil, tc.checkRequest, func(t *testing.T, req *http.Request) { t.Helper() })
			checkRequest = func(req *http.Request) { testRequest(t, req) }

			createResponse := x.IfThenElse(
				tc.createResponse != nil, tc.createResponse, func(t *testing.T, rw http.ResponseWriter) { t.Helper() })
			buildResponse = func(rw http.ResponseWriter) { createResponse(t, rw) }

			resolver := NewServerMetadataResolver(&endpoint.Endpoint{URL: tc.buildURL(t, srv.URL)})

			// WHEN
			sm, err := resolver.Get(context.TODO(), tc.args)

			// THEN
			tc.assert(t, endpointCalled, err, sm)
		})
	}
}
