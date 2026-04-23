package oauth2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

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
				RevealErrorDetails:  true,
				RevealRequiredScope: true,
				Realm:               "example",
				ErrorURI:            "https://example.com/error",
			},
			scopes: []string{"foo", "bar"},
			cause:  errorchain.New(pipeline.ErrAuthentication).CausedBy(pipeline.ErrArgument),
		},
		"invalid request without error details and request uri": {
			decorator:      BearerTokenUsageErrorDecorator{Enabled: true, Realm: "example"},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(pipeline.ErrArgument),
			expectedCode:   http.StatusBadRequest,
			expectedHeader: `Bearer realm="example", error="invalid_request"`,
		},
		"invalid request with all keys set": {
			decorator: BearerTokenUsageErrorDecorator{
				Enabled:             true,
				RevealErrorDetails:  true,
				RevealRequiredScope: true,
				ErrorURI:            "https://example.com/error",
				Realm:               "example",
			},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(pipeline.ErrArgument),
			expectedCode:   http.StatusBadRequest,
			expectedHeader: `Bearer realm="example", error_uri="https://example.com/error", error="invalid_request", error_description="argument error"`,
		},
		"insufficient scope without error details, scopes and request uri": {
			decorator:      BearerTokenUsageErrorDecorator{Enabled: true, Realm: "example"},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(ErrScopeMatch),
			expectedCode:   http.StatusForbidden,
			expectedHeader: `Bearer realm="example", error="insufficient_scope"`,
		},
		"insufficient scope with scopes scopes, but without error details and request uri": {
			decorator: BearerTokenUsageErrorDecorator{
				Enabled:             true,
				RevealRequiredScope: true,
				Realm:               "example",
			},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(ErrScopeMatch),
			expectedCode:   http.StatusForbidden,
			expectedHeader: `Bearer realm="example", error="insufficient_scope", scope="foo bar"`,
		},
		"insufficient scope with all keys set": {
			decorator: BearerTokenUsageErrorDecorator{
				Enabled:             true,
				RevealErrorDetails:  true,
				RevealRequiredScope: true,
				Realm:               "example",
				ErrorURI:            "https://example.com/error",
			},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(ErrScopeMatch),
			expectedCode:   http.StatusForbidden,
			expectedHeader: `Bearer realm="example", error_uri="https://example.com/error", error="insufficient_scope", scope="foo bar", error_description="scope matching error"`,
		},
		"invalid token without error details and request uri": {
			decorator:      BearerTokenUsageErrorDecorator{Enabled: true, Realm: "Please authenticate"},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(ErrAssertion),
			expectedCode:   http.StatusUnauthorized,
			expectedHeader: `Bearer realm="Please authenticate", error="invalid_token"`,
		},
		"invalid token with all keys set": {
			decorator: BearerTokenUsageErrorDecorator{
				Enabled:             true,
				RevealErrorDetails:  true,
				RevealRequiredScope: true,
				ErrorURI:            "https://example.com/error",
				Realm:               "Please authenticate",
			},
			scopes:         []string{"foo", "bar"},
			cause:          errorchain.New(pipeline.ErrAuthentication).CausedBy(ErrAssertion),
			expectedCode:   http.StatusUnauthorized,
			expectedHeader: `Bearer realm="Please authenticate", error_uri="https://example.com/error", error="invalid_token", error_description="assertion error"`,
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
