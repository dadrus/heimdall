package oauth2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func TestBearerTokenUsageErrorDecoratorMerge(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		decorator BearerTokenUsageErrorDecorator
		other     BearerTokenUsageErrorDecorator
		expected  BearerTokenUsageErrorDecorator
	}{
		"keeps explicitly configured values": {
			decorator: BearerTokenUsageErrorDecorator{
				Enabled:             new(false),
				RevealErrorDetails:  new(false),
				RevealRequiredScope: new(false),
				ErrorURI:            "https://decorator.example/error",
				Realm:               "decorator",
				ResourceMetadataURI: "https://decorator.example/resource-metadata",
			},
			other: BearerTokenUsageErrorDecorator{
				Enabled:             new(true),
				RevealErrorDetails:  new(true),
				RevealRequiredScope: new(true),
				ErrorURI:            "https://other.example/error",
				Realm:               "other",
				ResourceMetadataURI: "https://other.example/resource-metadata",
			},
			expected: BearerTokenUsageErrorDecorator{
				Enabled:             new(false),
				RevealErrorDetails:  new(false),
				RevealRequiredScope: new(false),
				ErrorURI:            "https://decorator.example/error",
				Realm:               "decorator",
				ResourceMetadataURI: "https://decorator.example/resource-metadata",
			},
		},
		"uses other values for zero values": {
			decorator: BearerTokenUsageErrorDecorator{},
			other: BearerTokenUsageErrorDecorator{
				Enabled:             new(true),
				RevealErrorDetails:  new(true),
				RevealRequiredScope: new(true),
				ErrorURI:            "https://other.example/error",
				Realm:               "other",
				ResourceMetadataURI: "https://other.example/resource-metadata",
			},
			expected: BearerTokenUsageErrorDecorator{
				Enabled:             new(true),
				RevealErrorDetails:  new(true),
				RevealRequiredScope: new(true),
				ErrorURI:            "https://other.example/error",
				Realm:               "other",
				ResourceMetadataURI: "https://other.example/resource-metadata",
			},
		},
		"merges partially configured values": {
			decorator: BearerTokenUsageErrorDecorator{
				Enabled:  new(false),
				Realm:    "decorator",
				ErrorURI: "https://decorator.example/error",
			},
			other: BearerTokenUsageErrorDecorator{
				Enabled:             new(true),
				RevealErrorDetails:  new(true),
				RevealRequiredScope: new(true),
				ErrorURI:            "https://other.example/error",
				Realm:               "other",
				ResourceMetadataURI: "https://other.example/resource-metadata",
			},
			expected: BearerTokenUsageErrorDecorator{
				Enabled:             new(false),
				RevealErrorDetails:  new(true),
				RevealRequiredScope: new(true),
				ErrorURI:            "https://decorator.example/error",
				Realm:               "decorator",
				ResourceMetadataURI: "https://other.example/resource-metadata",
			},
		},
		"keeps nil and empty values if other is empty": {
			decorator: BearerTokenUsageErrorDecorator{},
			other:     BearerTokenUsageErrorDecorator{},
			expected:  BearerTokenUsageErrorDecorator{},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, tc.decorator.Merge(tc.other))
		})
	}
}

func TestBearerTokenUsageErrorDecoratorDecorateErrorResponse(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		decorator      BearerTokenUsageErrorDecorator
		scopes         []string
		cause          error
		expectedCode   int
		expectedHeader string
	}{
		"disabled": {
			decorator: BearerTokenUsageErrorDecorator{
				RevealErrorDetails:  new(true),
				RevealRequiredScope: new(true),
				Realm:               "example",
				ErrorURI:            "https://example.com/error",
			},
			scopes: []string{"foo", "bar"},
			cause:  errorchain.New(pipeline.ErrAuthentication).CausedBy(pipeline.ErrArgument),
		},
		"invalid request without error details and request uri": {
			decorator:      BearerTokenUsageErrorDecorator{Enabled: new(true), Realm: "example"},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(pipeline.ErrArgument),
			expectedCode:   http.StatusBadRequest,
			expectedHeader: `Bearer realm="example", error="invalid_request"`,
		},
		"invalid request with all keys set": {
			decorator: BearerTokenUsageErrorDecorator{
				Enabled:             new(true),
				RevealErrorDetails:  new(true),
				RevealRequiredScope: new(true),
				ErrorURI:            "https://example.com/error",
				Realm:               "example",
				ResourceMetadataURI: "https://example.com/resource-metadata",
			},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(pipeline.ErrArgument),
			expectedCode:   http.StatusBadRequest,
			expectedHeader: `Bearer realm="example", error_uri="https://example.com/error", resource_metadata="https://example.com/resource-metadata", error="invalid_request", error_description="argument error"`,
		},
		"insufficient scope without anything else": {
			decorator:      BearerTokenUsageErrorDecorator{Enabled: new(true)},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(ErrScopeMatch),
			expectedCode:   http.StatusForbidden,
			expectedHeader: `Bearer error="insufficient_scope"`,
		},
		"insufficient scope with scopes scopes, but without error details and request uri": {
			decorator: BearerTokenUsageErrorDecorator{
				Enabled:             new(true),
				RevealRequiredScope: new(true),
				Realm:               "example",
			},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(ErrScopeMatch),
			expectedCode:   http.StatusForbidden,
			expectedHeader: `Bearer realm="example", error="insufficient_scope", scope="foo bar"`,
		},
		"insufficient scope with all keys set": {
			decorator: BearerTokenUsageErrorDecorator{
				Enabled:             new(true),
				RevealErrorDetails:  new(true),
				RevealRequiredScope: new(true),
				Realm:               "example",
				ErrorURI:            "https://example.com/error",
			},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(ErrScopeMatch),
			expectedCode:   http.StatusForbidden,
			expectedHeader: `Bearer realm="example", error_uri="https://example.com/error", error="insufficient_scope", scope="foo bar", error_description="scope matching error"`,
		},
		"invalid token without error details and request uri": {
			decorator:      BearerTokenUsageErrorDecorator{Enabled: new(true), Realm: "Please authenticate"},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(ErrAssertion),
			expectedCode:   http.StatusUnauthorized,
			expectedHeader: `Bearer realm="Please authenticate", error="invalid_token"`,
		},
		"invalid token with all keys set": {
			decorator: BearerTokenUsageErrorDecorator{
				Enabled:             new(true),
				RevealErrorDetails:  new(true),
				RevealRequiredScope: new(true),
				ErrorURI:            "https://example.com/error",
				Realm:               "Please authenticate",
				ResourceMetadataURI: "https://example.com/resource-metadata",
			},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(ErrAssertion),
			expectedCode:   http.StatusUnauthorized,
			expectedHeader: `Bearer realm="Please authenticate", error_uri="https://example.com/error", resource_metadata="https://example.com/resource-metadata", error="invalid_token", error_description="assertion error"`,
		},
		"invalid token with resource metadata only": {
			decorator: BearerTokenUsageErrorDecorator{
				Enabled:             new(true),
				ResourceMetadataURI: "https://example.com/resource-metadata",
			},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(ErrAssertion),
			expectedCode:   http.StatusUnauthorized,
			expectedHeader: `Bearer resource_metadata="https://example.com/resource-metadata", error="invalid_token"`,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			response := pipeline.ErrorResponse{
				Headers: map[string][]string{"X-Test": {"preserved"}},
			}

			tc.decorator.Decorate(tc.cause, tc.scopes, &response)

			assert.Equal(t, tc.expectedCode, response.Code)

			if len(tc.expectedHeader) != 0 {
				require.Len(t, response.Headers, 2)
				assert.Equal(t, []string{tc.expectedHeader}, response.Headers[wwwAuthenticateHeader])
			} else {
				require.Len(t, response.Headers, 1)
			}

			assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
		})
	}
}
