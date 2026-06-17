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
		decorator TokenUsageErrorDecorator
		other     TokenUsageErrorDecorator
		expected  TokenUsageErrorDecorator
	}{
		"keeps explicitly configured values": {
			decorator: TokenUsageErrorDecorator{
				Enabled:              new(false),
				IncludeErrorDetails:  new(false),
				IncludeRequiredScope: new(false),
				ErrorURI:             "https://decorator.example/error",
				Realm:                "decorator",
			},
			other: TokenUsageErrorDecorator{
				Enabled:              new(true),
				IncludeErrorDetails:  new(true),
				IncludeRequiredScope: new(true),
				ErrorURI:             "https://other.example/error",
				Realm:                "other",
			},
			expected: TokenUsageErrorDecorator{
				Enabled:              new(false),
				IncludeErrorDetails:  new(false),
				IncludeRequiredScope: new(false),
				ErrorURI:             "https://decorator.example/error",
				Realm:                "decorator",
			},
		},
		"uses other values for zero values": {
			decorator: TokenUsageErrorDecorator{},
			other: TokenUsageErrorDecorator{
				Enabled:              new(true),
				IncludeErrorDetails:  new(true),
				IncludeRequiredScope: new(true),
				ErrorURI:             "https://other.example/error",
				Realm:                "other",
			},
			expected: TokenUsageErrorDecorator{
				Enabled:              new(true),
				IncludeErrorDetails:  new(true),
				IncludeRequiredScope: new(true),
				ErrorURI:             "https://other.example/error",
				Realm:                "other",
			},
		},
		"merges partially configured values": {
			decorator: TokenUsageErrorDecorator{
				Enabled:  new(false),
				Realm:    "decorator",
				ErrorURI: "https://decorator.example/error",
			},
			other: TokenUsageErrorDecorator{
				Enabled:              new(true),
				IncludeErrorDetails:  new(true),
				IncludeRequiredScope: new(true),
				ErrorURI:             "https://other.example/error",
				Realm:                "other",
			},
			expected: TokenUsageErrorDecorator{
				Enabled:              new(false),
				IncludeErrorDetails:  new(true),
				IncludeRequiredScope: new(true),
				ErrorURI:             "https://decorator.example/error",
				Realm:                "decorator",
			},
		},
		"keeps nil and empty values if other is empty": {
			decorator: TokenUsageErrorDecorator{},
			other:     TokenUsageErrorDecorator{},
			expected:  TokenUsageErrorDecorator{},
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
		decorator      TokenUsageErrorDecorator
		cause          error
		expectedCode   int
		expectedHeader string
	}{
		"disabled": {
			decorator: TokenUsageErrorDecorator{
				IncludeErrorDetails:  new(true),
				IncludeRequiredScope: new(true),
				Realm:                "example",
				ErrorURI:             "https://example.com/error",
			},
			cause: errorchain.New(pipeline.ErrAuthentication).CausedBy(pipeline.ErrArgument),
		},
		"malformed request without error details and error uri": {
			decorator:      TokenUsageErrorDecorator{Enabled: new(true), Realm: "example"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(NewInvalidRequestError(TypeBearer, "")),
			expectedCode:   http.StatusBadRequest,
			expectedHeader: `Bearer realm="example", error="invalid_request"`,
		},
		"malformed request with all keys set": {
			decorator: TokenUsageErrorDecorator{
				Enabled:              new(true),
				IncludeErrorDetails:  new(true),
				IncludeRequiredScope: new(true),
				ErrorURI:             "https://example.com/error",
				Realm:                "example",
			},
			cause: errorchain.New(pipeline.ErrAuthentication).CausedBy(
				NewInvalidRequestError(TypeBearer, "malformed request: invalid JWT format")),
			expectedCode:   http.StatusBadRequest,
			expectedHeader: `Bearer realm="example", error="invalid_request", error_uri="https://example.com/error", error_description="malformed request: invalid JWT format"`,
		},
		"insufficient scope without anything else": {
			decorator:      TokenUsageErrorDecorator{Enabled: new(true)},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(NewInsufficientScopeError(TypeBearer, "", nil)),
			expectedCode:   http.StatusForbidden,
			expectedHeader: `Bearer error="insufficient_scope"`,
		},
		"insufficient scope with scopes, but without error details and error uri": {
			decorator: TokenUsageErrorDecorator{
				Enabled:              new(true),
				IncludeRequiredScope: new(true),
				Realm:                "example",
			},
			cause: errorchain.New(pipeline.ErrAuthentication).CausedBy(
				NewInsufficientScopeError(TypeBearer, "scope matching error", []string{"foo", "bar"})),
			expectedCode:   http.StatusForbidden,
			expectedHeader: `Bearer realm="example", error="insufficient_scope", scope="foo bar"`,
		},
		"insufficient scope with all keys set": {
			decorator: TokenUsageErrorDecorator{
				Enabled:              new(true),
				IncludeErrorDetails:  new(true),
				IncludeRequiredScope: new(true),
				Realm:                "example",
				ErrorURI:             "https://example.com/error",
			},
			cause: errorchain.New(pipeline.ErrAuthentication).CausedBy(
				NewInsufficientScopeError(TypeBearer, "scope matching error", []string{"foo", "bar"})),
			expectedCode:   http.StatusForbidden,
			expectedHeader: `Bearer realm="example", error="insufficient_scope", error_uri="https://example.com/error", error_description="scope matching error", scope="foo bar"`,
		},
		"invalid token without error details and error uri": {
			decorator:      TokenUsageErrorDecorator{Enabled: new(true), Realm: "Please authenticate"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(NewInvalidTokenError(TypeBearer, "")),
			expectedCode:   http.StatusUnauthorized,
			expectedHeader: `Bearer realm="Please authenticate", error="invalid_token"`,
		},
		"invalid token with all keys set": {
			decorator: TokenUsageErrorDecorator{
				Enabled:              new(true),
				IncludeErrorDetails:  new(true),
				IncludeRequiredScope: new(true),
				ErrorURI:             "https://example.com/error",
				Realm:                "Please authenticate",
			},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(NewInvalidTokenError(TypeBearer, "assertion error")),
			expectedCode:   http.StatusUnauthorized,
			expectedHeader: `Bearer realm="Please authenticate", error="invalid_token", error_uri="https://example.com/error", error_description="assertion error"`,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			response := pipeline.ErrorResponse{
				Headers: map[string][]string{"X-Test": {"preserved"}},
			}

			tc.decorator.Decorate(tc.cause, &response)

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
